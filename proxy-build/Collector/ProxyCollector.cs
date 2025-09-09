using Octokit;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Configuration;
using SingBoxLib.Configuration.Inbound;
using SingBoxLib.Configuration.Outbound;
using SingBoxLib.Configuration.Outbound.Abstract;
using SingBoxLib.Parsing;
using SingBoxLib.Runtime;
using SingBoxLib.Runtime.Testing;
using System.Collections.Concurrent;
using System.Text;
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
            _config.GeoLiteCountryDbPath,    // GeoLite2-Country.mmdb
            _config.GeoLiteAsnDbPath         // GeoLite2-ASN.mmdb
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

        var profiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Collected {profiles.Count} unique profiles with protocols: {included}.");

        var workingResults = new List<UrlTestResult>();

        var maxRetries = _config.maxRetriesCount;
        LogToConsole($"Minimum active proxies >= {_config.MinActiveProxies} with maximum {_config.maxRetriesCount} retries.");

        // Profil yang belum terbukti aktif → mulai dari semua profil
        var remainingProfiles = profiles.ToList();

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            // Round-robin: kalau habis, balik lagi ke awal
            var testUrl = _config.TestUrls[(attempt - 1) % _config.TestUrls.Length];
            
            LogToConsole($"Attempt {attempt} / {maxRetries} testing with URL: {testUrl}");

            if (!remainingProfiles.Any())
            {
                LogToConsole("No remaining profiles left to test.");
                break;
            }

            var attemptResults = await TestProfiles(remainingProfiles, testUrl);

            var newSuccesses = attemptResults
                .Where(r => r.Success && !workingResults.Any(x => x.Profile.Address == r.Profile.Address))
                .ToList();

            foreach (var s in newSuccesses)
                workingResults.Add(s);

            LogToConsole(
                $"Attempt {attempt} / {maxRetries}: testing {remainingProfiles.Count} nodes → {newSuccesses.Count} new, {workingResults.Count} total active."
            );

            if (workingResults.Count >= _config.MinActiveProxies)
            {
                LogToConsole($"Reached minimum required {_config.MinActiveProxies} active proxies, stopping retries.");
                break;
            }

            // Update daftar tersisa: hanya yang gagal di attempt ini
            var successAddresses = new HashSet<string>(
                attemptResults.Where(r => r.Success).Select(r => r.Profile.Address!)
            );
            remainingProfiles = remainingProfiles
                .Where(p => !successAddresses.Contains(p.Address!))
                .ToList();
        }

        if (workingResults.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({workingResults.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        LogToConsole("Compiling results...");
        var finalResults = workingResults
            .Select(r => new { TestResult = r, CountryInfo = _ipToCountryResolver.GetCountry(r.Profile.Address!) })
            .GroupBy(p => p.CountryInfo.CountryCode)
            .Select
            (
                x => x.OrderBy(x => x.TestResult.Delay)
                    .WithIndex()
                    .Take(_config.MaxProxiesPerCountry)
                    .Select(x =>
                    {
                        var profile = x.Item.TestResult.Profile;
                        var countryInfo = x.Item.CountryInfo;
                        var ispRaw = countryInfo.Isp ?? string.Empty;

                        // Bersihkan titik dan suffix formal
                        ispRaw = ispRaw.Replace(".", "").Trim();

                        // Daftar suffix formal yang ingin dihapus
                        var formalSuffixes = new[] { "SAS", "INC", "LTD", "LLC", "CORP", "CO", "GMBH", "SA", "SRO" };

                        // Pisahkan kata
                        var ispParts = ispRaw.Split(new[] { ' ', '-' }, StringSplitOptions.RemoveEmptyEntries)
                            .Where(w => !formalSuffixes.Contains(w.ToUpperInvariant()))
                            .ToArray();

                        // Ambil kata pertama dan kedua jika ada
                        var ispName = ispParts.Length >= 2
                            ? $"{ispParts[0]} {ispParts[1]}"
                            : (ispParts.Length == 1 ? ispParts[0] : "Unknown");

                        // Gunakan untuk profile name
                        profile.Name = $"{countryInfo.CountryCode} {x.Index + 1} - {ispName}";

                        return new { Profile = profile, CountryCode = countryInfo.CountryCode };
                    })
            )
            .SelectMany(x => x)
            .OrderBy(x => x.CountryCode)
            .Select(x => x.Profile)
            .ToList();

        LogToConsole("Uploading results...");
        await CommitResults(finalResults.ToList());

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }


    private async Task CommitResults(List<ProfileItem> profiles)
    {
        LogToConsole($"Uploading V2ray Subscription...");
        await CommitV2raySubscriptionResult(profiles);
    }

    private async Task CommitV2raySubscriptionResult(List<ProfileItem> profiles)
    {
        var finalResult = new StringBuilder();
        foreach (var profile in profiles)
        {
            var profileName = profile.Name;
            profile.Name = HttpUtility.UrlPathEncode(profile.Name);
            finalResult.AppendLine(profile.ToProfileUrl());
            profile.Name = profileName;
        }

        var outputPath = _config.V2rayFormatResultPath;

        // Pastikan folder tujuan ada
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(outputPath, finalResult.ToString());
        LogToConsole($"Subscription file written to {outputPath}");
    }

    private async Task<IReadOnlyCollection<UrlTestResult>> TestProfiles(IEnumerable<ProfileItem> profiles, string testUrl)
    {
        var tester = new ParallelUrlTester(
            new SingBoxWrapper(_config.SingboxPath),
            // A list of open local ports, must be equal or bigger than total test thread count
            // make sure they are not occupied by other applications running on your system
            20000,
            // max number of concurrent testing
            _config.MaxThreadCount,
            // timeout in miliseconds
            _config.Timeout,
            // retry count (will still do the retries even if proxy works, returns fastest result)
            1024,
            testUrl);

        var workingResults = new ConcurrentBag<UrlTestResult>();
        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>((result =>
        {
            if (result.Success)
                workingResults.Add(result);
        })), default);
        return workingResults;
    }


    private async Task<IReadOnlyCollection<ProfileItem>> CollectProfilesFromConfigSources()
    {
        using var client = new HttpClient()
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        var profiles = new ConcurrentBag<ProfileItem>();
        await Parallel.ForEachAsync(_config.Sources,new ParallelOptions {MaxDegreeOfParallelism = _config.MaxThreadCount }, async (source, ct) =>
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
            catch(Exception ex)
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
                // Skip jika protokol tidak ada di IncludedProtocols
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

public static class HelperExtentions
{
    public static IEnumerable<(int Index, T Item)> WithIndex<T>(this IEnumerable<T> items)
    {
        int index = 0;
        foreach (var item in items)
        {
            yield return (index++, item);
        }
    }
}
