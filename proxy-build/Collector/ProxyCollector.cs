using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Parsing;
using SingBoxLib.Runtime;
using SingBoxLib.Runtime.Testing;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;
    private readonly IPToCountryResolver _resolver;

    // Dipindah ke static readonly agar tidak dibuat berulang di loop
    private static readonly string[] FormalSuffixes =
    {
        "SAS","INC","LTD","LLC","CORP","CO","SA","SRO","ASN","LIMITED",
        "COMPANY","ASIA","CLOUD","INTERNATIONAL","PROVIDER","ISLAND",
        "PRIVATE","ONLINE","OF","AS","BV","HK"
    };

    public ProxyCollector()
    {
        _config = CollectorConfig.Instance;
        _resolver = new IPToCountryResolver(
            _config.GeoLiteCountryDbPath,
            _config.GeoLiteAsnDbPath
        );
    }

    private void LogToConsole(string log)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");
    }

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        // Ambil semua profile dari sumber
        var allProfiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();

        // Pisahkan profil vless dan non-vless
        var vlessProfiles = allProfiles
            .Where(p => p.ToProfileUrl().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var liteProfiles = allProfiles.Except(vlessProfiles).ToList();

        LogToConsole($"Total profiles: {allProfiles.Count}, NON-VLESS: {liteProfiles.Count}, VLESS: {vlessProfiles.Count}");

        // Test Lite untuk non-vless
        var liteTestResult = liteProfiles.Any() ? await RunLiteTest(liteProfiles) : new List<ProfileItem>();
        LogToConsole($"Active proxies (Lite): {liteTestResult.Count}");

        // Test SingBoxWrapper untuk vless
        var vlessTestResult = vlessProfiles.Any() ? await RunSingboxTest(vlessProfiles) : new List<ProfileItem>();
        LogToConsole($"Active proxies (Singbox): {vlessTestResult.Count}");

        // Gabungkan hasil
        var combinedResults = liteTestResult.Concat(vlessTestResult).ToList();
        LogToConsole($"Total active proxies after tests: {combinedResults.Count}");

        if (combinedResults.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({combinedResults.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        // Resolusi negara & limit per country
        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();
        foreach (var profile in combinedResults)
        {
            if (string.IsNullOrEmpty(profile.Address))
                continue; // skip profile tanpa alamat

            var country = _resolver.GetCountry(profile.Address);
            countryMap[profile] = country;

            // Normalisasi ISP
            var ispRaw = string.IsNullOrEmpty(country.Isp) ? "Unknown" : country.Isp;
            ispRaw = ispRaw.Replace(".", "").Replace(",", "").Trim();

            var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                                 .Where(w => !FormalSuffixes.Contains(w.ToUpperInvariant()))
                                 .ToArray();

            var ispName = ispParts.Length >= 2
                ? $"{ispParts[0]} {ispParts[1]}"
                : (ispParts.Length == 1 ? ispParts[0] : "Unknown");

            // Hitung indeks unik per negara
            var idx = combinedResults.Count(p => countryMap.ContainsKey(p) && countryMap[p].CountryCode == country.CountryCode);
            profile.Name = $"{country.CountryCode} {idx} - {ispName}";
        }

        // --- hasil tanpa limit (semua aktif)
        var allGrouped = combinedResults
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g)
            .ToList();

        var noLimitListPath = Path.Combine(Directory.GetCurrentDirectory(), "all_list.txt");
        await File.WriteAllLinesAsync(noLimitListPath, allGrouped.Select(p => p.ToProfileUrl()));
        LogToConsole($"Saved all_list.txt ({allGrouped.Count} proxies)");

        // --- hasil dengan limit per country
        var limited = combinedResults
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        var limitListPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        await File.WriteAllLinesAsync(limitListPath, limited.Select(p => p.ToProfileUrl()));
        LogToConsole($"Saved list.txt ({limited.Count} proxies)");

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task<IReadOnlyCollection<ProfileItem>> CollectProfilesFromConfigSources()
    {
        using var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(8) };
        var profiles = new ConcurrentBag<ProfileItem>();

        await Parallel.ForEachAsync(_config.Sources, new ParallelOptions { MaxDegreeOfParallelism = _config.MaxThreadCount }, async (source, ct) =>
        {
            try
            {
                var subContents = await client.GetStringAsync(source);
                foreach (var profile in TryParseSubContent(subContents))
                {
                    profiles.Add(profile);
                }
                LogToConsole($"Collected {profiles.Count} proxies from {source}");
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
                var data = Convert.FromBase64String(subContent);
                subContent = Encoding.UTF8.GetString(data);
            }
            catch { }

            using var reader = new StringReader(subContent);
            string? line;
            while ((line = reader.ReadLine()?.Trim()) is not null)
            {
                if (_config.IncludedProtocols.Length > 0 && !_config.IncludedProtocols.Any(p => line.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ProfileItem? profile = null;
                try { profile = ProfileParser.ParseProfileUrl(line); } catch { }
                if (profile is not null) yield return profile;
            }
        }
    }

    private async Task<List<ProfileItem>> RunLiteTest(List<ProfileItem> profiles)
    {
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "collect_list.txt");
        await File.WriteAllLinesAsync(listPath, profiles.Select(p => p.ToProfileUrl()));

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "bash",
                Arguments = _config.EnableDebug == "true"
                    ? $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}'\""
                    : $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}' > /dev/null 2>&1\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };
            proc.Start();
            await proc.WaitForExitAsync();

            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (!File.Exists(jsonPath)) return new List<ProfileItem>();

            using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
            var nodes = doc.RootElement.GetProperty("nodes");
            var result = new List<ProfileItem>();

            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("isok", out var isokProp) && isokProp.ValueKind == JsonValueKind.True &&
                    node.TryGetProperty("link", out var linkProp))
                {
                    var profile = ProfileParser.ParseProfileUrl(linkProp.GetString()!);
                    if (profile != null) result.Add(profile);
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            LogToConsole($"Lite test failed: {ex.Message}");
            return new List<ProfileItem>();
        }
    }

    private async Task<List<ProfileItem>> RunSingboxTest(List<ProfileItem> profiles)
    {
        if (!profiles.Any()) return new List<ProfileItem>();

        var tester = new ParallelUrlTester(
            new SingBoxWrapper(_config.SingboxPath),
            20000,
            _config.MaxThreadCount,
            _config.Timeout,
            1024,
            "http://www.gstatic.com/generate_204"
        );

        var workingResults = new ConcurrentBag<UrlTestResult>();
        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>(r =>
        {
            if (r.Success) workingResults.Add(r);
        }), default);

        return workingResults.Select(r => r.Profile).ToList();
    }
}
