using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using ProxyCollector.Models;
using ProxyCollector.Services;
using ProxyCollector.Configuration;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;

    public ProxyCollector()
    {
        _config = CollectorConfig.Instance;
    }

    private void LogToConsole(string log)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");
    }

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        var profiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Collected {profiles.Count} unique profiles with protocols: {included}.");
        LogToConsole($"Minimum active proxies >= {_config.MinActiveProxies}.");

        if (profiles.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({profiles.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        LogToConsole("Compiling results...");
        var finalResults = profiles.ToList();

        // tulis list.txt (base64) untuk lite
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        var plain = string.Join("\n", finalResults.Select(p => p.ToProfileUrl()));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
        await File.WriteAllTextAsync(listPath, base64);
        LogToConsole($"Temporary list written to {listPath} (base64-encoded, {finalResults.Count} entries)");

        // jalankan lite test
        var liteOk = await RunLiteTest(listPath);
        var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
        if (!liteOk || !File.Exists(outputPath))
        {
            LogToConsole("Lite test failed — skipping upload.");
            await File.WriteAllTextAsync("skip_push.flag", "lite test failed");
            return;
        }

        // --- Proses IPToCountryResolver ---
        LogToConsole("Resolving countries for active proxies...");
        var resolver = new IPToCountryResolver();
        var lines = await File.ReadAllLinesAsync(outputPath);
        var parsedProfiles = new List<ProfileItem>();

        // dictionary untuk simpan hasil country per profile
        var countryMap = new Dictionary<ProfileItem, CountryInfo>();

        foreach (var line in lines)
        {
            ProfileItem? profile = null;
            try { profile = ProfileParser.ParseProfileUrl(line); } catch { }
            if (profile == null) continue;

            try
            {
                var host = profile.Address;
                if (string.IsNullOrEmpty(host))
                    continue;

                var country = await resolver.GetCountry(host);
                countryMap[profile] = country;
                
                var isp = string.IsNullOrEmpty(country.Isp) ? "UnknownISP" : country.Isp;
                var ispParts = isp.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                var ispTwoWords = ispParts.Length > 1
                    ? string.Join(" ", ispParts.Take(2))
                    : (ispParts.Length == 1 ? ispParts[0] : "UnknownISP");
                var idx = parsedProfiles.Count(p => countryMap.ContainsKey(p) &&
                                                    countryMap[p].CountryCode == country.CountryCode);

                profile.Name = Uri.UnescapeDataString($"{country.CountryCode} {idx + 1} - {ispTwoWords}");
            }
            catch (Exception ex)
            {
                LogToConsole($"[WARN] Failed resolve {profile.Address}: {ex.Message}");
            }
        }

        // batasi jumlah per country
        var grouped = parsedProfiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        LogToConsole($"Final proxy count after country limit: {grouped.Count}");


        // tulis hasil final ke list.txt
        try { File.Delete(listPath); } catch { }
        await File.WriteAllLinesAsync(listPath, grouped.Select(p => p.ToProfileUrl()));
        try { File.Delete(outputPath); } catch { }

        // upload hasil
        LogToConsole("Uploading results...");
        await CommitResultsFromFile(listPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task<bool> RunLiteTest(string listPath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bash",
                Arguments = $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} -test '{listPath}' > /dev/null 2>&1\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };

            proc.Start();
            await proc.WaitForExitAsync();

            LogToConsole($"Lite test finished with exit code {proc.ExitCode}");

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            if (proc.ExitCode == 0 && File.Exists(outputPath))
            {
                return true;
            }
            else
            {
                LogToConsole("Warning: lite did not produce a valid output.txt or exited with error.");
                if (File.Exists(outputPath))
                    LogToConsole($"Note: output.txt exists but lite exit code = {proc.ExitCode}.");
                return false;
            }
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to run lite test: {ex.Message}");
            return false;
        }
    }

    private async Task CommitResultsFromFile(string listPath)
    {
        LogToConsole("Uploading V2ray Subscription...");

        if (!File.Exists(listPath))
        {
            LogToConsole("list.txt not found, skipping upload.");
            return;
        }

        var outputPath = _config.V2rayFormatResultPath;
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        File.Copy(listPath, outputPath, true);
        LogToConsole($"Subscription file written to {outputPath}");

        await Task.CompletedTask;
    }

    private async Task<IReadOnlyCollection<ProfileItem>> CollectProfilesFromConfigSources()
    {
        using var client = new HttpClient()
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        var profiles = new ConcurrentBag<ProfileItem>();
        await Parallel.ForEachAsync(_config.Sources, new ParallelOptions { MaxDegreeOfParallelism = _config.MaxThreadCount }, async (source, ct) =>
        {
            try
            {
                var count = 0;
                var subContents = await client.GetStringAsync(source);
                foreach (var profile in TryParseSubContent(subContents))
                {
                    profiles.Add(profile);
                    count++;
                }
                LogToConsole($"Collected {count} proxies from {source}");
            }
            catch (Exception ex)
            {
                LogToConsole($"Failed to fetch {source}. error: {ex.Message}");
            }
        });

        return profiles;

        IEnumerable<ProfileItem> TryParseSubContent(string subContent)
        {
            try
            {
                var contentData = Convert.FromBase64String(subContent);
                subContent = Encoding.UTF8.GetString(contentData);
            }
            catch { }

            using var reader = new StringReader(subContent);
            string? line = null;
            while ((line = reader.ReadLine()?.Trim()) is not null)
            {
                if (_config.IncludedProtocols.Length > 0 &&
                    !_config.IncludedProtocols.Any(proto => line.StartsWith(proto, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                ProfileItem? profile = null;
                try
                {
                    profile = ProfileParser.ParseProfileUrl(line);
                }
                catch { }

                if (profile is not null)
                {
                    yield return profile;
                }
            }
        }
    }
}
