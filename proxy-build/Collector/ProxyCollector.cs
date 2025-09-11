using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Parsing;
using System.Text.Json;

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

    private static string TryBase64Decode(string input)
    {
        try
        {
            int mod4 = input.Length % 4;
            if (mod4 > 0)
                input = input.PadRight(input.Length + (4 - mod4), '=');

            var data = Convert.FromBase64String(input);
            return Encoding.UTF8.GetString(data);
        }
        catch
        {
            return input;
        }
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

        LogToConsole("Compiling results...");
        var finalResults = profiles
            .Where(p => p != null) // filter null
            .ToList();

        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");

        // Hapus emoji dan convert ke string in-memory
        var linesMemory = finalResults
            .Select(p =>
            {
            try { return RemoveEmojis(p.ToProfileUrl()); }
            catch { return null; }
            })
            .Where(line => line != null)
            .ToList()!;

        // Tulis ke disk sekali saja
        await File.WriteAllLinesAsync(listPath, linesMemory, Encoding.UTF8);
        LogToConsole($"Final list written to {listPath} ({linesMemory.Count} entries)");

        var buildJson = await RunLiteTest(listPath);
        if (buildJson is null)
        {
            LogToConsole("Lite test failed — skipping upload.");
            await File.WriteAllTextAsync("skip_push.flag", "lite test failed");
            return;
        }

        var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
        var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
        SaveActiveLinksToFile(jsonPath, outputPath);

        int activeProxyCount = 0;
        if (File.Exists(outputPath))
        {
            activeProxyCount = File.ReadLines(outputPath).Count();
        }

        if (activeProxyCount < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({activeProxyCount}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        // --- Resolusi negara & ISP ---
        LogToConsole("Resolving countries for active proxies...");
        var resolver = new IPToCountryResolver(
            _config.GeoLiteCountryDbPath,
            _config.GeoLiteAsnDbPath
        );

        var lines = await File.ReadAllLinesAsync(outputPath);
        var parsedProfiles = new List<ProfileItem>();
        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();

        foreach (var line in lines)
        {
            ProfileItem? profile = null;
            try { profile = ProfileParser.ParseProfileUrl(line); } catch { }
            if (profile == null) continue;

            try
            {
                string? host = profile.Address;

                if (string.IsNullOrEmpty(host))
                {
                    var decoded = TryBase64Decode(line);
                    if (decoded.StartsWith("{"))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(decoded);
                            if (doc.RootElement.TryGetProperty("add", out var addProp))
                                host = addProp.GetString();
                        }
                        catch { }
                    }
                }

                if (string.IsNullOrEmpty(host))
                    continue;

                var country = resolver.GetCountry(host);
                countryMap[profile] = country;

                var ispRaw = string.IsNullOrEmpty(country.Isp) ? "Unknown" : country.Isp;
                ispRaw = ispRaw.Replace(".", "")
                                .Replace(",", "")
                                .Trim();

                var formalSuffixes = new[] { "SAS", "INC", "LTD", "LLC", "CORP", "CO", "SA", "SRO", "ASN", "LIMITED", "COMPANY", "ASIA", "CLOUD", "INTERNATIONAL", "PROVIDER", "ISLAND", "PRIVATE", "ONLINE", "OF", "AS", "BV", "HK" , "MSN", "BMC", "PTE" };

                var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(w => !formalSuffixes.Contains(w.ToUpperInvariant()))
                    .ToArray();

                var ispName = ispParts.Length >= 2
                    ? $"{ispParts[0]} {ispParts[1]}"
                    : (ispParts.Length == 1 ? ispParts[0] : "Unknown");

                var idx = parsedProfiles.Count(p => countryMap.ContainsKey(p) &&
                                                    countryMap[p].CountryCode == country.CountryCode);

                profile.Name = $"{country.CountryCode} {idx + 1} - {ispName}";
                parsedProfiles.Add(profile);
            }
            catch (Exception ex)
            {
                LogToConsole($"[WARN] Failed resolve {profile.Address}: {ex.Message}");
            }
        }

        var grouped = parsedProfiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        LogToConsole($"Final proxy count after country limit: {grouped.Count}");

        try { File.Delete(listPath); } catch { }
        await File.WriteAllLinesAsync(listPath, grouped.Select(p => p.ToProfileUrl()));
        try { File.Delete(outputPath); } catch { }

        LogToConsole("Uploading results...");
        await CommitResultsFromFile(listPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private void SaveActiveLinksToFile(string jsonPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
        var nodes = doc.RootElement.GetProperty("nodes");
        var result = new List<(string Link, int Ping)>();

        foreach (var node in nodes.EnumerateArray())
        {
            if (node.TryGetProperty("isok", out var isokProp) &&
                isokProp.ValueKind == JsonValueKind.True &&
                node.TryGetProperty("ping", out var pingProp))
            {
                var pingStr = pingProp.GetString();
                if (int.TryParse(pingStr, out int ping) && ping > 0)
                {
                    if (node.TryGetProperty("link", out var linkProp))
                    {
                        var link = linkProp.GetString();
                        if (!string.IsNullOrEmpty(link))
                        {
                            result.Add((link, ping));
                        }
                    }
                }
            }
        }

        var ordered = result.OrderBy(r => r.Ping).Select(r => r.Link).ToList();
        File.WriteAllLines(outputPath, ordered);
        LogToConsole($"Saved {ordered.Count} active proxies to {outputPath}, ordered by ping.");
    }

    private static string RemoveEmojis(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var pattern = new System.Text.RegularExpressions.Regex(@"[\p{Cs}\p{So}\p{Sk}]",
            System.Text.RegularExpressions.RegexOptions.Compiled);

        return pattern.Replace(input, "");
    }

    private async Task<string?> RunLiteTest(string listPath)
    {
        try
        {
            var debug = string.Equals(
                _config.EnableDebug,
                "true",
                StringComparison.OrdinalIgnoreCase
            );

            var psi = new ProcessStartInfo
            {
                FileName = "bash",
                Arguments = debug
                    ? $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}'\""
                    : $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}' > /dev/null 2>&1\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };
            proc.Start();
            await proc.WaitForExitAsync();

            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (proc.ExitCode == 0 && File.Exists(jsonPath))
                return jsonPath;

            LogToConsole($"Lite test failed with exit code {proc.ExitCode}");
            if (File.Exists(jsonPath))
                LogToConsole("Note: out.json exists but may be invalid.");
            return null;
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to run Lite test: {ex.Message}");
            return null;
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
                    yield return profile;
            }
        }
    }
}
