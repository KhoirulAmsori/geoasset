using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
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

    private void LogToConsole(string log) =>
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");

    private static string RemoveEmojis(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        var pattern = new System.Text.RegularExpressions.Regex(@"[\p{Cs}\p{So}\p{Sk}]",
            System.Text.RegularExpressions.RegexOptions.Compiled);
        return pattern.Replace(input, "");
    }

    private static bool LooksLikeBase64(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        return s.Length % 4 == 0 && s.All(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=');
    }

    private static string TryBase64Decode(string input)
    {
        if (LooksLikeBase64(input))
        {
            try
            {
                int mod4 = input.Length % 4;
                if (mod4 > 0) input = input.PadRight(input.Length + (4 - mod4), '=');
                return Encoding.UTF8.GetString(Convert.FromBase64String(input));
            }
            catch { }
        }
        return input;
    }

    private List<ProfileItem> ParseProfilesFromContent(string content)
    {
        var profiles = new List<ProfileItem>();
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()?.Trim()) != null)
        {
            if (_config.IncludedProtocols.Length > 0 &&
                !_config.IncludedProtocols.Any(proto => line.StartsWith(proto, StringComparison.OrdinalIgnoreCase)))
                continue;

            try
            {
                var profile = ProfileParser.ParseProfileUrl(line);
                if (profile != null) profiles.Add(profile);
            }
            catch { }
        }
        return profiles;
    }

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var allSourcesContent = new List<string>();
        var allProfiles = new List<ProfileItem>();

        // --- Ambil semua profile dari semua source ---
        foreach (var source in _config.Sources)
        {
            string content;
            try
            {
                content = await client.GetStringAsync(source);
                content = content.Trim();
                if (LooksLikeBase64(content))
                    content = Encoding.UTF8.GetString(Convert.FromBase64String(content));
            }
            catch (Exception ex)
            {
                LogToConsole($"Failed to fetch {source}: {ex.Message}");
                continue;
            }

            allSourcesContent.Add(content);

            var profiles = ParseProfilesFromContent(content);
            allProfiles.AddRange(profiles);
        }

        // Log jumlah unik proxy dan protokol
        var uniqueProfiles = allProfiles
            .GroupBy(p => p.ToProfileUrl())
            .Select(g => g.First())
            .ToList();

        var protocols = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Collected {uniqueProfiles.Count} unique profiles with protocols: {protocols}.");
        LogToConsole($"Minimum active proxies >= {_config.MinActiveProxies}.");

        // --- Tahap 1: Lite per source ---
        foreach (var (source, content) in _config.Sources.Zip(allSourcesContent, (s, c) => (s, c)))
        {
            LogToConsole($"Processing source: {source}");
            var profiles = ParseProfilesFromContent(content);
            if (!profiles.Any())
            {
                LogToConsole($"No valid proxies found in source {source}");
                continue;
            }

            var tempListPath = Path.Combine(Directory.GetCurrentDirectory(), "temp_list.txt");
            await File.WriteAllLinesAsync(tempListPath, profiles.Select(p => RemoveEmojis(p.ToProfileUrl())));

            // Hapus out.json lama sebelum Lite
            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (File.Exists(jsonPath)) File.Delete(jsonPath);

            var liteJson = await RunLiteTest(tempListPath);
            if (liteJson == null)
            {
                LogToConsole($"Lite test failed for source {source}");
                continue;
            }

            var tempOutputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            SaveActiveLinksToFile(liteJson, tempOutputPath);

            var activeCount = File.Exists(tempOutputPath) ? File.ReadAllLines(tempOutputPath).Length : 0;
            LogToConsole($"Source {source} has {activeCount} active proxies");
        }

        // --- Tahap 2: Lite untuk semua source digabung ---
        LogToConsole("Running final Lite test on all sources combined...");

        var combinedProfiles = uniqueProfiles; // Lite akan membuang duplikat otomatis
        if (!combinedProfiles.Any())
        {
            LogToConsole("No valid proxies collected from all sources. Exiting.");
            return;
        }

        var combinedListPath = Path.Combine(Directory.GetCurrentDirectory(), "combined_list.txt");
        await File.WriteAllLinesAsync(combinedListPath, combinedProfiles.Select(p => RemoveEmojis(p.ToProfileUrl())));

        // Hapus out.json sebelum Lite final
        var finalJsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
        if (File.Exists(finalJsonPath)) File.Delete(finalJsonPath);

        var finalLiteJson = await RunLiteTest(combinedListPath);
        if (finalLiteJson == null)
        {
            LogToConsole("Final Lite test failed, skipping upload.");
            return;
        }

        var finalOutputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
        SaveActiveLinksToFile(finalLiteJson, finalOutputPath);

        var finalLines = File.Exists(finalOutputPath) ? await File.ReadAllLinesAsync(finalOutputPath) : Array.Empty<string>();
        var allActiveProxies = new List<ProfileItem>();
        foreach (var line in finalLines)
        {
            try
            {
                var profile = ProfileParser.ParseProfileUrl(line);
                if (profile != null) allActiveProxies.Add(profile);
            }
            catch { }
        }

        LogToConsole($"Total active proxies after final Lite test: {allActiveProxies.Count}");

        if (allActiveProxies.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({allActiveProxies.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        // --- Resolving IP ---
        LogToConsole("Resolving countries for active proxies...");
        using var resolver = new IPToCountryResolver(_config.GeoLiteCountryDbPath, _config.GeoLiteAsnDbPath);

        var parsedProfiles = new List<ProfileItem>();
        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();

        foreach (var profile in allActiveProxies)
        {
            if (profile == null || string.IsNullOrEmpty(profile.Address)) continue;
            string host = profile.Address;

            try
            {
                var country = resolver.GetCountry(host);
                countryMap[profile] = country;

                var ispRaw = string.IsNullOrEmpty(country.Isp) ? "Unknown" : country.Isp;
                ispRaw = ispRaw.Replace(".", "").Replace(",", "").Trim();

                var formalSuffixes = new[] { "SAS","INC","LTD","LLC","CORP","CO","SA","SRO","ASN","LIMITED","COMPANY","ASIA","CLOUD","INTERNATIONAL","PROVIDER","ISLAND","PRIVATE","ONLINE","OF","AS","BV","HK","MSN","BMC","PTE" };
                var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(w => !formalSuffixes.Contains(w.ToUpperInvariant()))
                    .ToArray();

                var ispName = ispParts.Length >= 2 ? $"{ispParts[0]} {ispParts[1]}" : (ispParts.Length == 1 ? ispParts[0] : "Unknown");

                var idx = parsedProfiles.Count(p => countryMap.ContainsKey(p) && countryMap[p].CountryCode == country.CountryCode);

                profile.Name = $"{country.CountryCode} {idx + 1} - {ispName}";
                parsedProfiles.Add(profile);
            }
            catch (Exception ex)
            {
                LogToConsole($"[WARN] Failed resolve {profile.Address}: {ex.Message}");
            }
        }

        // Batasi proxy per country
        var grouped = parsedProfiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        await File.WriteAllLinesAsync(Path.Combine(Directory.GetCurrentDirectory(), "list.txt"), grouped.Select(p => p.ToProfileUrl()));

        LogToConsole($"Final proxy count after country limit: {grouped.Count}");

        // --- Upload / Commit ---
        await CommitResultsFromFile(Path.Combine(Directory.GetCurrentDirectory(), "list.txt"));

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
                            result.Add((link, ping));
                    }
                }
            }
        }

        var ordered = result.OrderBy(r => r.Ping).Select(r => r.Link).ToList();
        File.WriteAllLines(outputPath, ordered);

        LogToConsole($"Saved {ordered.Count} active proxies to {outputPath}, ordered by ping.");
    }

    private async Task<string?> RunLiteTest(string listPath)
    {
        try
        {
            var debug = string.Equals(_config.EnableDebug, "true", StringComparison.OrdinalIgnoreCase);

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
}
