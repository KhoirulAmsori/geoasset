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

public class ProxyCollector : IDisposable
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
            _config.GeoLiteAsnDbPath,
            20
        );
    }

    private static string GetProxyKey(ProfileItem profile)
    {
        var url = profile.ToProfileUrl();

        var fragmentIndex = url.IndexOf('#');
        if (fragmentIndex != -1)
            url = url.Substring(0, fragmentIndex);

        if (url.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var b64 = url.Substring("vmess://".Length);
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var add = root.TryGetProperty("add", out var addProp) ? addProp.GetString() ?? "" : "";
                return $"vmess|{add.ToLowerInvariant()}";
            }
            catch
            {
                return url;
            }
        }

        if (url.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
        {
            var ssKey = TryParseSsKey(url);
            if (!string.IsNullOrEmpty(ssKey))
            {
                var parts = ssKey.Split('|');
                if (parts.Length >= 3)
                    return $"ss|{parts[2]}";
                return ssKey;
            }
        }

        try
        {
            var uri = new Uri(url);
            var scheme = uri.Scheme.ToLowerInvariant();
            var host = uri.Host.ToLowerInvariant();

            return $"{scheme}|{host}";
        }
        catch
        {
            return url;
        }
    }

    private static string TryParseSsKey(string url)
    {
        try
        {
            if (!url.StartsWith("ss://", StringComparison.OrdinalIgnoreCase)) return "";

            var after = url.Substring("ss://".Length);

            if (after.Contains("@"))
            {
                var parts = after.Split('@', 2);
                var userinfo = parts[0];
                var hostpart = parts.Length > 1 ? parts[1] : "";
                var hostAndPort = hostpart.Split(new[] { '/', '?' }, 2)[0];
                var hostOnly = hostAndPort.Contains(":") ? hostAndPort.Split(':', 2)[0] : hostAndPort;
                return string.Join("|", new[] { "ss", userinfo, hostOnly }.Where(s => !string.IsNullOrEmpty(s)));
            }

            var stop = after.IndexOfAny(new[] { '/', '?', '#' });
            var b64 = stop == -1 ? after : after.Substring(0, stop);
            var padded = b64;
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "="; break;
            }

            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
            if (decoded.Contains("@"))
            {
                var seg = decoded.Split('@', 2);
                var userinfo = seg[0];
                var hostpart = seg[1];
                var hostAndPort = hostpart.Split(new[] { '/', '?' }, 2)[0];
                var hostOnly = hostAndPort.Contains(":") ? hostAndPort.Split(':', 2)[0] : hostAndPort;
                return string.Join("|", new[] { "ss", userinfo, hostOnly }.Where(s => !string.IsNullOrEmpty(s)));
            }
            else
            {
                return "ss|" + decoded;
            }
        }
        catch
        {
            return "";
        }
    }

    private void LogToConsole(string log) =>
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        var allProfiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";
        LogToConsole($"Get unique profiles with protocols: {included}.");

        var vlessProfiles = allProfiles
            .Where(p => p.ToProfileUrl().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            .ToList();

        var liteProfiles = allProfiles.Except(vlessProfiles).ToList();

        LogToConsole($"NON-VLESS: {liteProfiles.Count}, VLESS: {vlessProfiles.Count}");

        LogToConsole("Compiling results...");

        var liteTestResult = liteProfiles.Any() ? await RunLiteTest(liteProfiles) : new List<ProfileItem>();
        LogToConsole($"Active proxies (Lite): {liteTestResult.Count}");
        
        var vlessTestResult = vlessProfiles.Any() ? await RunSingboxTest(vlessProfiles) : new List<ProfileItem>();
        LogToConsole($"Active proxies (Singbox): {vlessTestResult.Count}");

        var combinedResults = liteTestResult.Concat(vlessTestResult).ToList();
        LogToConsole($"Total active proxies after tests: {combinedResults.Count}");

        if (combinedResults.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({combinedResults.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();
        var processedProfiles = new List<ProfileItem>();

        foreach (var profile in combinedResults)
        {
            if (string.IsNullOrEmpty(profile.Address))
                continue;

            var country = _resolver.GetCountry(profile.Address);
            if (string.Equals(country.CountryCode, "Unknown", StringComparison.OrdinalIgnoreCase))
                continue;

            countryMap[profile] = country;

            var ispName = NormalizeIspName(country.Isp);
            AssignProxyName(profile, country, ispName);

            processedProfiles.Add(profile);
        }

        var allGrouped = processedProfiles
            .GroupBy(p => GetProxyKey(p))
            .Select(g => g.First())
            .ToList();

        allGrouped = ReindexProfiles(allGrouped, countryMap);
        await SaveProfileList("all_list.txt", allGrouped);

        var limited = processedProfiles
            .GroupBy(p => GetProxyKey(p))
            .Select(g => g.First())
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        limited = ReindexProfiles(limited, countryMap);
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
        string ispName)
    {
        var cc = country.CountryCode ?? "ZZ";
        profile.Name = $"{cc} - {ispName}";
    }

    private static List<ProfileItem> ReindexProfiles(
        List<ProfileItem> profiles,
        Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo> countryMap)
    {
        return profiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .SelectMany(group =>
            {
                int idx = 1;
                return group.Select(p =>
                {
                    var cc = countryMap[p].CountryCode ?? "ZZ";
                    var ispName = p.Name.Split(" - ", 2).Last();
                    p.Name = $"{cc} {idx} - {ispName}";
                    idx++;
                    return p;
                });
            })
            .OrderBy(p => p.Name)
            .ToList();
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
            "https://www.youtube.com/generate_204"
        );

        var workingResults = new ConcurrentBag<UrlTestResult>();
        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>(r =>
        {
            if (r.Success) workingResults.Add(r);
        }), default);

        return workingResults.Select(r => r.Profile).ToList();
    }

    public void Dispose()
    {
        _resolver?.Dispose();
    }
}
