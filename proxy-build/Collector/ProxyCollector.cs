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
using SingBoxLib.Runtime;
using SingBoxLib.Runtime.Testing;
using System.Web;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;
    private readonly IPToCountryResolver _ipToCountryResolver;

    public ProxyCollector()
    {
        _config = CollectorConfig.Instance;
        _ipToCountryResolver = new IPToCountryResolver(
            _config.GeoLiteCountryDbPath,
            _config.GeoLiteAsnDbPath
        );
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

        var allProfiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Get {allProfiles.Count} unique profiles with protocols: {included}.");

        // Pisahkan profil berdasarkan protokol
        var vlessProfiles = allProfiles.Where(p => p.Protocol == "vless").ToList();
        var otherProfiles = allProfiles.Where(p => p.Protocol != "vless").ToList();

        // Koleksi hasil pengujian yang berhasil
        var activeProfiles = new ConcurrentBag<ProfileItem>();

        // Bagian 1: Uji profil non-VLESS menggunakan Lite
        if (otherProfiles.Any())
        {
            LogToConsole($"Testing {otherProfiles.Count} non-VLESS proxies using Lite...");
            await TestWithLite(otherProfiles, activeProfiles);
        }

        // Bagian 2: Uji profil VLESS menggunakan Singbox
        if (vlessProfiles.Any())
        {
            LogToConsole($"Testing {vlessProfiles.Count} VLESS proxies using Singbox...");
            await TestWithSingbox(vlessProfiles, activeProfiles);
        }

        var finalResults = activeProfiles.ToList();
        var activeProxyCount = finalResults.Count;

        if (activeProxyCount < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({activeProxyCount}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        LogToConsole($"Total active proxies: {activeProxyCount}");

        // --- Resolusi negara & ISP dan Penamaan Ulang ---
        var countryMap = new Dictionary<ProfileItem, IPToCountryResolver.ProxyCountryInfo>();

        foreach (var profile in finalResults)
        {
            try
            {
                var host = profile.Address;
                if (string.IsNullOrEmpty(host)) continue;

                var country = _ipToCountryResolver.GetCountry(host);
                countryMap[profile] = country;

                var ispRaw = string.IsNullOrEmpty(country.Isp) ? "Unknown" : country.Isp.Replace(".", "").Replace(",", "").Trim();
                var formalSuffixes = new[] { "SAS", "INC", "LTD", "LLC", "CORP", "CO", "SA", "SRO", "ASN", "LIMITED", "COMPANY", "ASIA", "CLOUD", "INTERNATIONAL", "PROVIDER", "ISLAND", "PRIVATE", "ONLINE", "OF", "AS", "BV", "HK", "MSN", "BMC", "PTE" };

                var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(w => !formalSuffixes.Contains(w.ToUpperInvariant()))
                    .ToArray();

                var ispName = ispParts.Length >= 2
                    ? $"{ispParts[0]} {ispParts[1]}"
                    : (ispParts.Length == 1 ? ispParts[0] : "Unknown");

                var idx = finalResults.Count(p => countryMap.ContainsKey(p) && countryMap[p].CountryCode == country.CountryCode);
                profile.Name = $"{country.CountryCode} {idx} - {ispName}";
            }
            catch (Exception ex)
            {
                LogToConsole($"[WARN] Failed resolve {profile.Address}: {ex.Message}");
            }
        }
        
        // --- hasil tanpa limit (semua proxy)
        var allGrouped = finalResults
            .OrderBy(p => countryMap.ContainsKey(p) ? countryMap[p].CountryCode ?? "ZZ" : "ZZ")
            .Select(p => p.ToProfileUrl())
            .ToList();
        
        var noLimitListPath = Path.Combine(Directory.GetCurrentDirectory(), "all_list.txt");
        await File.WriteAllLinesAsync(noLimitListPath, allGrouped, Encoding.UTF8);
        LogToConsole($"Total proxy count (no limit): {allGrouped.Count}");


        // --- hasil dengan limit per country
        var limitedGrouped = finalResults
            .GroupBy(p => countryMap.ContainsKey(p) ? countryMap[p].CountryCode ?? "ZZ" : "ZZ")
            .OrderBy(g => g.Key)
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .Select(p => p.ToProfileUrl())
            .ToList();
        
        var limitListPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        await File.WriteAllLinesAsync(limitListPath, limitedGrouped, Encoding.UTF8);
        LogToConsole($"Final proxy count after country limit: {limitedGrouped.Count}");

        await CommitResults(limitListPath, noLimitListPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task TestWithLite(List<ProfileItem> profiles, ConcurrentBag<ProfileItem> activeProfiles)
    {
        var collectListPath = Path.Combine(Directory.GetCurrentDirectory(), "collect_list.txt");
        await File.WriteAllLinesAsync(collectListPath, profiles.Select(p => p.ToProfileUrl()));

        var jsonPath = await RunLiteTest(collectListPath);
        if (jsonPath is null)
        {
            LogToConsole("Lite test failed or produced no output.");
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
            var nodes = doc.RootElement.GetProperty("nodes");
            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("isok", out var isokProp) && isokProp.ValueKind == JsonValueKind.True)
                {
                    if (node.TryGetProperty("link", out var linkProp))
                    {
                        var link = linkProp.GetString();
                        if (!string.IsNullOrEmpty(link))
                        {
                            var profile = ProfileParser.ParseProfileUrl(link);
                            if (profile != null)
                            {
                                activeProfiles.Add(profile);
                            }
                        }
                    }
                }
            }
            LogToConsole($"Lite test found {activeProfiles.Count} active proxies.");
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to process Lite output: {ex.Message}");
        }
    }

    private async Task TestWithSingbox(List<ProfileItem> profiles, ConcurrentBag<ProfileItem> activeProfiles)
    {
        var tester = new ParallelUrlTester(
            new SingBoxWrapper(_config.SingboxPath),
            20000,
            _config.MaxThreadCount,
            _config.Timeout,
            1024,
            "http://www.gstatic.com/generate_204");

        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>((result =>
        {
            if (result.Success)
            {
                activeProfiles.Add(result.Profile);
            }
        })), default);

        LogToConsole($"Singbox test found {profiles.Count(p => activeProfiles.Any(ap => ap.Address == p.Address))} active VLESS proxies.");
    }

    private async Task CommitResults(params string[] sourcePaths)
    {
        foreach (var sourcePath in sourcePaths)
        {
            if (!File.Exists(sourcePath))
            {
                LogToConsole($"{sourcePath} not found, skipping upload.");
                continue;
            }

            var fileName = Path.GetFileName(sourcePath);
            var outputDir = Directory.GetCurrentDirectory();
            var outputPath = Path.Combine(outputDir, fileName);

            if (sourcePath != outputPath)
            {
                File.Copy(sourcePath, outputPath, true);
            }

            LogToConsole($"Created output: {outputPath}");
        }

        await Task.CompletedTask;
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
}
