using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

using ProxyCollector.Configuration;
using ProxyCollector.Services; // untuk IPToCountryResolver + CountryInfo
using SingBoxLib.Configuration;
using SingBoxLib.Parsing;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;
    private readonly IPToCountryResolver _resolver;

    public ProxyCollector()
    {
        _config = CollectorConfig.Instance;
        _resolver = new IPToCountryResolver();
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

        // tulis list.txt base64 untuk lite
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        var plain = string.Join("\n", finalResults.Select(p => p.ToProfileUrl()));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
        await File.WriteAllTextAsync(listPath, base64);
        LogToConsole($"Temporary list written to {listPath} (base64-encoded, {finalResults.Count} entries)");

        // jalankan lite test
        var liteOk = await RunLiteTest(listPath);

        if (!liteOk)
        {
            LogToConsole("Lite test failed — skipping upload.");
            await File.WriteAllTextAsync("skip_push.flag", "lite test failed");
            return;
        }

        // Setelah lite sukses, proses hasil output.txt dengan IPToCountryResolver
        var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
        if (File.Exists(outputPath))
        {
            LogToConsole("Resolving countries & renaming profiles...");

            var content = await File.ReadAllTextAsync(outputPath);
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(content));

            var parsedProfiles = new List<ProfileItem>();
            using (var reader = new StringReader(decoded))
            {
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    try
                    {
                        var p = ProfileParser.ParseProfileUrl(line.Trim());
                        if (p != null) parsedProfiles.Add(p);
                    }
                    catch { }
                }
            }

            var countryMap = new Dictionary<ProfileItem, CountryInfo>();

            foreach (var profile in parsedProfiles)
            {
                try
                {
                    var server = profile.ServerAddress; // gunakan ServerAddress
                    var country = await _resolver.GetCountry(server);
                    countryMap[profile] = country;

                    // Ambil hanya 2 kata pertama ISP
                    var isp = string.IsNullOrEmpty(country.Isp) ? "UnknownISP" : country.Isp;
                    var ispParts = isp.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    var ispTwoWords = ispParts.Length > 1
                        ? string.Join(" ", ispParts.Take(2))
                        : ispParts.FirstOrDefault() ?? "UnknownISP";

                    // Hitung index per country
                    var idx = parsedProfiles.Count(p => countryMap.ContainsKey(p) &&
                                                        countryMap[p].CountryCode == country.CountryCode);

                    profile.Name = Uri.UnescapeDataString($"{country.CountryCode} {idx} - {ispTwoWords}");
                }
                catch (Exception ex)
                {
                    LogToConsole($"Failed to resolve country for {profile.ServerAddress}: {ex.Message}");
                }
            }

            // Tulis ulang list.txt hasil rename → base64 encode
            var newPlain = string.Join("\n", parsedProfiles.Select(p => p.ToProfileUrl()));
            var newBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(newPlain));

            File.Delete(listPath);
            await File.WriteAllTextAsync(listPath, newBase64);
            LogToConsole("Profiles renamed & written back to list.txt");
        }

        // Upload
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
                LogToConsole("Lite test succeeded, output.txt ready");
                return true;
            }
            else
            {
                LogToConsole("Warning: lite did not produce a valid output.txt or exited with error.");
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
