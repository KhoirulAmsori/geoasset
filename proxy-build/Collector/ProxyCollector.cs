using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Parsing;
using SingBoxLib.Runtime.Testing;
using SingBoxLib.Runtime;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text;
using System.Threading.Tasks;
using System;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;
    private readonly IPToCountryResolver _resolver;

    // Ganti ke HashSet untuk O(1) lookup
    private static readonly HashSet<string> FormalSuffixes = new(StringComparer.OrdinalIgnoreCase)
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

    private static string GetProxyKey(ProfileItem profile)
    {
        var sb = new StringBuilder();
        var proto = profile.Protocol?.ToLowerInvariant() ?? "";

        sb.Append(proto);
        sb.Append("://");

        switch (proto)
        {
            case "vless":
            case "vmess":
                sb.Append(profile.UserId ?? "");
                break;

            case "trojan":
                sb.Append(profile.Password ?? "");
                break;

            case "ss":
            case "shadowsocks":
                sb.Append(profile.Method ?? "");
                sb.Append(":");
                sb.Append(profile.Password ?? "");
                break;
        }

        sb.Append("@");
        sb.Append(profile.Address ?? "");
        sb.Append(":");
        sb.Append(profile.Port);

        // kalau mau pembeda antar transport (ws/tcp/grpc), bisa tambahkan:
        // sb.Append("?type=");
        // sb.Append(profile.Type?.ToLowerInvariant() ?? "");

        return sb.ToString();
    }

    private void LogToConsole(string log) =>
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        // Ambil semua profile dari sumber (sudah unik)
        var allProfiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";
        LogToConsole($"Get unique profiles with protocols: {included}.");

        // Pisahkan VLESS dan non-VLESS
        var vlessProfiles = allProfiles
            .Where(p => p.ToProfileUrl().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var liteProfiles = allProfiles.Except(vlessProfiles).ToList();

        LogToConsole($"NON-VLESS: {liteProfiles.Count}, VLESS: {vlessProfiles.Count}");

        LogToConsole("Compiling results...");

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

        // Resolusi negara & penamaan
        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();
        var countryCounters = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in combinedResults)
        {
            if (string.IsNullOrEmpty(profile.Address))
                continue;

            var country = _resolver.GetCountry(profile.Address);
            countryMap[profile] = country;

            var ispName = NormalizeIspName(country.Isp);
            AssignProxyName(profile, country, ispName, countryCounters);
        }

        // --- hasil tanpa limit
        var allGrouped = combinedResults
            .GroupBy(p => GetProxyKey(p))
            .Select(g => g.First()) // ambil satu saja untuk tiap key
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g)
            .ToList();

        await SaveProfileList("all_list.txt", allGrouped);

        // --- hasil dengan limit per country
        var limited = combinedResults
            .GroupBy(p => GetProxyKey(p))
            .Select(g => g.First())
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        await SaveProfileList("list.txt", limited);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private static string NormalizeIspName(string? isp)
    {
        if (string.IsNullOrWhiteSpace(isp)) return "Unknown";

        var ispRaw = isp.Replace(".", "").Replace(",", "").Trim();

        var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                             .Where(w => !FormalSuffixes.Contains(w))
                             .ToArray();

        return ispParts.Length switch
        {
            >= 2 => $"{ispParts[0]} {ispParts[1]}",
            1 => ispParts[0],
            _ => "Unknown"
        };
    }

    private static void AssignProxyName(ProfileItem profile,
        IPToCountryResolver.ProxyCountryInfo country,
        string ispName,
        Dictionary<string, int> counters)
    {
        var cc = country.CountryCode ?? "ZZ";
        if (!counters.TryGetValue(cc, out var idx))
            idx = 0;

        idx++;
        counters[cc] = idx;

        profile.Name = $"{cc} {idx} - {ispName}";
    }

    private async Task SaveProfileList(string fileName, List<ProfileItem> profiles)
    {
        var path = Path.Combine(Directory.GetCurrentDirectory(), fileName);
        await File.WriteAllLinesAsync(path, profiles.Select(p => p.ToProfileUrl()));
        LogToConsole($"Saved {fileName} ({profiles.Count} proxies)");
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
                LogToConsole($"Get {count} proxies from {source}");
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

    private async Task<List<ProfileItem>> RunLiteTest(List<ProfileItem> profiles)
    {
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "collect_list.txt");
        await File.WriteAllLinesAsync(listPath, profiles.Select(p => p.ToProfileUrl()));

        var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
        if (File.Exists(jsonPath))
            File.Delete(jsonPath);

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

            if (!File.Exists(jsonPath)) return new List<ProfileItem>();

            using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
            var nodes = doc.RootElement.GetProperty("nodes");
            var result = new List<ProfileItem>();

            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("isok", out var isokProp) &&
                    isokProp.ValueKind == JsonValueKind.True &&
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
