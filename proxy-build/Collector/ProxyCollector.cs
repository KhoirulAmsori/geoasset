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
        var url = profile.ToProfileUrl();

        // 1) buang fragment (#...)
        var hashIndex = url.IndexOf('#');
        if (hashIndex >= 0) url = url.Substring(0, hashIndex);

        // 2) vmess
        if (url.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var b64 = url.Substring("vmess://".Length);
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                string id = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                string add = root.TryGetProperty("add", out var addProp) ? addProp.GetString() ?? "" : "";
                string port = root.TryGetProperty("port", out var portProp) ? portProp.ToString() : "";

                string net = root.TryGetProperty("net", out var netProp) ? (netProp.GetString() ?? "") : "";
                string host = root.TryGetProperty("host", out var hostProp) ? (hostProp.GetString() ?? "") : "";
                string path = root.TryGetProperty("path", out var pathProp) ? (pathProp.GetString() ?? "") : "";
                string tls = root.TryGetProperty("tls", out var tlsProp) ? (tlsProp.GetString() ?? "") : "";

                path = NormalizePath(path);

                var parts = new List<string> { "vmess", id, add, port };

                if (!string.IsNullOrEmpty(net)) parts.Add("net=" + net.ToLowerInvariant());
                if (!string.IsNullOrEmpty(host)) parts.Add("host=" + host.ToLowerInvariant());
                if (!string.IsNullOrEmpty(path) && path != "/") parts.Add("path=" + path);
                if (!string.IsNullOrEmpty(tls)) parts.Add("tls=" + tls.ToLowerInvariant());

                return string.Join("|", parts);
            }
            catch
            {
                return NormalizeGenericUrlKey(url);
            }
        }

        // 3) selain vmess → pakai Uri
        try
        {
            var uri = new Uri(url);

            var scheme = uri.Scheme.ToLowerInvariant();
            var userInfo = uri.UserInfo;
            var host = uri.Host;
            var port = uri.Port;
            var q = ParseQueryString(uri.Query);

            if (scheme == "vless")
            {
                var uuid = userInfo.Split(':').FirstOrDefault() ?? "";
                var security = q.TryGetValue("security", out var secVal) ? secVal : q.TryGetValue("encryption", out var e) ? e : "";
                var sni = q.TryGetValue("sni", out var s) ? s : "";
                var type = q.TryGetValue("type", out var t) ? t : "";
                var path = q.TryGetValue("path", out var p) ? NormalizePath(p) : "";

                var parts = new List<string> { "vless", uuid, host, port.ToString() };

                if (!string.IsNullOrEmpty(security)) parts.Add("security=" + security.ToLowerInvariant());
                if (!string.IsNullOrEmpty(sni)) parts.Add("sni=" + sni.ToLowerInvariant());
                if (!string.IsNullOrEmpty(type) && !type.Equals("tcp", StringComparison.OrdinalIgnoreCase)) parts.Add("type=" + type.ToLowerInvariant());
                if (!string.IsNullOrEmpty(path) && path != "/") parts.Add("path=" + path);

                return string.Join("|", parts);
            }

            if (scheme == "trojan")
            {
                var password = userInfo.Split(':').FirstOrDefault() ?? "";
                var security = q.TryGetValue("security", out var secVal) ? secVal : "";
                var sni = q.TryGetValue("sni", out var s) ? s : "";

                var parts = new List<string> { "trojan", password, host, port.ToString() };
                if (!string.IsNullOrEmpty(security)) parts.Add("security=" + security.ToLowerInvariant());
                if (!string.IsNullOrEmpty(sni)) parts.Add("sni=" + sni.ToLowerInvariant());

                return string.Join("|", parts);
            }

            if (scheme == "ss")
            {
                var ssKey = TryParseSsKey(url);
                if (!string.IsNullOrEmpty(ssKey)) return ssKey;

                var user = userInfo;
                var parts = new List<string> { "ss", user, host, port.ToString() }.Where(s => !string.IsNullOrEmpty(s)).ToList();
                return string.Join("|", parts);
            }

            return NormalizeGenericUrlKey(url);
        }
        catch
        {
            return NormalizeGenericUrlKey(url);
        }
    }

    // ===== Helper functions =====
    private static string NormalizePath(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return "/";
        try { raw = Uri.UnescapeDataString(raw); } catch { }
        raw = raw.Replace('\\', '/').Trim();
        if (!raw.StartsWith("/")) raw = "/" + raw;
        while (raw.Contains("//")) raw = raw.Replace("//", "/");
        return raw == "" ? "/" : raw;
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return dict;
        var q = query.StartsWith("?") ? query.Substring(1) : query;
        foreach (var part in q.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split(new[] { '=' }, 2);
            var key = Uri.UnescapeDataString(kv[0]).Trim();
            var value = kv.Length > 1 ? Uri.UnescapeDataString(kv[1]).Trim() : "";
            dict[key] = value;
        }
        return dict;
    }

    private static string NormalizeGenericUrlKey(string url)
    {
        var parts = url.Split(new[] { '?' }, 2);
        var basePart = parts[0];
        if (parts.Length == 1) return basePart;

        var query = parts[1];
        var keep = query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p =>
                !p.StartsWith("encryption=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("security=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("host=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("sni=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("path=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("serviceName=", StringComparison.OrdinalIgnoreCase) &&
                !p.StartsWith("type=", StringComparison.OrdinalIgnoreCase)
            )
            .OrderBy(p => p)
            .ToArray();

        return keep.Length > 0 ? basePart + "?" + string.Join("&", keep) : basePart;
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
                var host = hostpart.Split(new[] { '/', '?' }, 2)[0];
                return string.Join("|", new[] { "ss", userinfo, host }.Where(s => !string.IsNullOrEmpty(s)));
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
                return string.Join("|", new[] { "ss", userinfo, hostpart }.Where(s => !string.IsNullOrEmpty(s)));
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
            "https://www.youtube.com/generate_204"
        );

        var workingResults = new ConcurrentBag<UrlTestResult>();
        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>(r =>
        {
            if (r.Success) workingResults.Add(r);
        }), default);

        return workingResults.Select(r => r.Profile).ToList();
    }
}
