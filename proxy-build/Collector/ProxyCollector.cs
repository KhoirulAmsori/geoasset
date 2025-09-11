using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Parsing;

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

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var allActiveProxies = new List<ProfileItem>();

        foreach (var source in _config.Sources)
        {
            LogToConsole($"Processing source: {source}");
            string sourceContent;
            try
            {
                sourceContent = await client.GetStringAsync(source);
            }
            catch (Exception ex)
            {
                LogToConsole($"Failed to fetch {source}: {ex.Message}");
                continue;
            }

            if (LooksLikeBase64(sourceContent))
            {
                try { sourceContent = Encoding.UTF8.GetString(Convert.FromBase64String(sourceContent)); }
                catch { }
            }

            // Parse menjadi ProfileItem
            var profiles = new List<ProfileItem>();
            using var reader = new StringReader(sourceContent);
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

            if (!profiles.Any())
            {
                LogToConsole($"No valid proxies found in source {source}");
                continue;
            }

            // Tulis sementara untuk Lite
            var tempListPath = Path.Combine(Directory.GetCurrentDirectory(), "temp_list.txt");
            await File.WriteAllLinesAsync(tempListPath, profiles.Select(p => p.ToProfileUrl()).Select(RemoveEmojis));

            // Jalankan Lite
            var liteJsonPath = await RunLiteTest(tempListPath);
            if (liteJsonPath == null)
            {
                LogToConsole($"Lite test failed for source {source}");
                continue;
            }

            // Ambil proxy aktif via SaveActiveLinksToFile
            var tempOutputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            SaveActiveLinksToFile(liteJsonPath, tempOutputPath);

            var activeLines = File.Exists(tempOutputPath) ? await File.ReadAllLinesAsync(tempOutputPath) : Array.Empty<string>();
            var activeProfiles = new List<ProfileItem>();
            foreach (var activeLine in activeLines)
            {
                try
                {
                    var profile = ProfileParser.ParseProfileUrl(activeLine);
                    if (profile != null) activeProfiles.Add(profile);
                }
                catch { }
            }

            LogToConsole($"Source {source} has {activeProfiles.Count} active proxies");
            allActiveProxies.AddRange(activeProfiles);
        }

        LogToConsole($"Total active proxies from all sources: {allActiveProxies.Count}");

        if (allActiveProxies.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({allActiveProxies.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }
        
        // Hapus duplikat sebelum lanjut resolusi IP
        allActiveProxies = allActiveProxies
            .GroupBy(p => p.ToProfileUrl())   // grup berdasarkan string URL proxy
            .Select(g => g.First())           // ambil yang pertama dari grup
            .ToList();

        // --- Resolving IP
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

        // --- Group by country limit
        var grouped = parsedProfiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        LogToConsole($"Final proxy count after country limit: {grouped.Count}");

        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        await File.WriteAllLinesAsync(listPath, grouped.Select(p => p.ToProfileUrl()), Encoding.UTF8);

        LogToConsole("Uploading results...");
        await CommitResultsFromFile(listPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
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
