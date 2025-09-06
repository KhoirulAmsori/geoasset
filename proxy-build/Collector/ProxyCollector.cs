using Octokit;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using SingBoxLib.Configuration;
using SingBoxLib.Configuration.Inbound;
using SingBoxLib.Configuration.Outbound;
using SingBoxLib.Configuration.Outbound.Abstract;
using SingBoxLib.Configuration.Route;
using SingBoxLib.Configuration.Shared;
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
        _ipToCountryResolver = new IPToCountryResolver();
    }

    private void LogToConsole(string log)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");
    }

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        var rawProfiles = await CollectProfilesFromConfigSources();
        LogToConsole($"Collected {rawProfiles.Count} raw profiles.");

        var profiles = rawProfiles
            .DistinctBy(p => p.ToProfileUrl())
            .ToList();

        var removedCount = rawProfiles.Count - profiles.Count;
        if (removedCount > 0)
            LogToConsole($"Removed {removedCount} duplicate profiles (initial stage).");

        LogToConsole($"Using {profiles.Count} unique profiles for testing.");

        LogToConsole($"Beginning UrlTest process.");
        var workingResults = (await TestProfiles(profiles));
        LogToConsole($"Testing has finished, found {workingResults.Count} working profiles.");

        LogToConsole($"Compiling results...");
        var finalResults = workingResults
            .Select(r => new
            {
                TestResult = r,
                CountryInfo = _ipToCountryResolver.GetCountry(r.Profile.Address!).Result
            })
            .GroupBy(p => p.CountryInfo.CountryCode)
            .SelectMany(g =>
            {
                var profiles = g.Take(_config.MaxProxiesPerCountry)
                            .Select(x => x.TestResult.Profile)
                            .ToList();

                // Penomoran ulang supaya tidak ada loncat angka
                for (int i = 0; i < profiles.Count; i++)
                {
                    profiles[i].Name = $"{g.Key}-{i + 1}";
                }

                return profiles;
            })
            .ToList();

        LogToConsole($"Writing results...");
        await CommitResults(finalResults);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }


    private async Task CommitResults(List<ProfileItem> profiles)
    {
        LogToConsole($"Saving V2ray Subscription...");
        await CommitV2raySubscriptionResult(profiles);
    }

    private async Task CommitV2raySubscriptionResult(List<ProfileItem> profiles)
    {
        var encodedProfiles = profiles
            .Select(p =>
            {
                var originalName = p.Name;
                p.Name = HttpUtility.UrlPathEncode(p.Name);
                var url = p.ToProfileUrl();
                p.Name = originalName;
                return new { Profile = p, Url = url };
            })
            .ToList();

        // Hapus fragment `#` saat deduplikasi
        var distinctProfiles = encodedProfiles
            .DistinctBy(x => x.Url.Split('#')[0])
            .OrderBy(x => x.Profile.Name)
            .ToList();

        var removedCount = encodedProfiles.Count - distinctProfiles.Count;
        if (removedCount > 0)
            LogToConsole($"Removed {removedCount} duplicate profiles before writing final file.");

        var finalResult = new StringBuilder();
        foreach (var item in distinctProfiles)
        {
            finalResult.AppendLine(item.Url);
        }

        var outputPath = _config.V2rayFormatResultPath;

        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(outputPath, finalResult.ToString());
        LogToConsole($"Subscription file written to {outputPath} (total {distinctProfiles.Count} unique entries)");
    }


    private async Task<IReadOnlyCollection<UrlTestResult>> TestProfiles(IEnumerable<ProfileItem> profiles)
    {
        var tester = new ParallelUrlTester(
            new SingBoxWrapper(_config.SingboxPath),
            20000,
            _config.MaxThreadCount,
            _config.Timeout,
            1024,
            "https://www.gstatic.com/generate_204");

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
