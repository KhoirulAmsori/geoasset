using Octokit;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using System.Collections.Concurrent;
using System.Diagnostics;
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

        var profiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Collected {profiles.Count} unique profiles with protocols: {included}.");

        var workingResults = new List<UrlTestResult>();
        var maxRetries = _config.maxRetriesCount;
        LogToConsole($"Minimum active proxies >= {_config.MinActiveProxies} with maximum {maxRetries} retries.");

        var remainingProfiles = profiles.ToList();

        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            var testUrl = _config.TestUrls[(attempt - 1) % _config.TestUrls.Length];
            LogToConsole($"Attempt {attempt} / {maxRetries} testing with URL: {testUrl}");

            if (!remainingProfiles.Any())
            {
                LogToConsole("No remaining profiles left to test.");
                break;
            }

            var attemptResults = await TestProfiles(remainingProfiles, _config.LitePath, _config.LiteConfigPath);

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
            .Select(r => new {
                TestResult = r,
                CountryInfo = _ipToCountryResolver.GetCountry(ExtractHost(r.Profile.Address!)).Result
            })
            .GroupBy(p => p.CountryInfo.CountryCode)
            .Select(
                x => x.OrderBy(x => x.TestResult.Delay)
                      .WithIndex()
                      .Take(_config.MaxProxiesPerCountry)
                      .Select(x =>
                      {
                          var profile = x.Item.TestResult.Profile;
                          var countryInfo = x.Item.CountryInfo;
                          var ispRaw = (countryInfo.Isp ?? string.Empty).Replace(".", "");
                          var ispParts = ispRaw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                          var ispName = ispParts.Length >= 2
                              ? $"{ispParts[0]} {ispParts[1]}"
                              : (ispParts.Length == 1 ? ispParts[0] : "Unknown");
                          profile.Name = $"{countryInfo.CountryCode} {x.Index + 1} - {ispName}";
                          return new { Profile = profile, CountryCode = countryInfo.CountryCode };
                      })
            )
            .SelectMany(x => x)
            .OrderBy(x => x.CountryCode)
            .Select(x => x.Profile)
            .ToList();

        LogToConsole("Uploading results...");
        await CommitResults(finalResults);

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
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(outputPath, finalResult.ToString());
        LogToConsole($"Subscription file written to {outputPath}");
    }

    // ===== Lite-based proxy testing =====
    private async Task<UrlTestResult> TestProfileWithLite(ProfileItem profile, string litePath, string configPath)
    {
        var result = new UrlTestResult
        {
            Profile = profile,
            Success = false,
            Delay = -1
        };

        var psi = new ProcessStartInfo
        {
            FileName = litePath,
            Arguments = $"--config {configPath} -test {profile.ToProfileUrl()}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = psi };
        var output = new StringBuilder();

        process.OutputDataReceived += (s, e) => { if (e.Data != null) { output.AppendLine(e.Data); LogToConsole(e.Data); } };
        process.ErrorDataReceived += (s, e) => { if (e.Data != null) { output.AppendLine(e.Data); LogToConsole(e.Data); } };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await process.WaitForExitAsync();

        foreach (var line in output.ToString().Split("\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains("elapse:"))
            {
                var parts = line.Split("elapse:");
                if (parts.Length > 1 && int.TryParse(parts[1].Replace("ms", "").Trim(), out int ping))
                {
                    result.Success = true;
                    result.Delay = ping;
                }
            }
        }

        return result;
    }

    private async Task<IReadOnlyCollection<UrlTestResult>> TestProfiles(IEnumerable<ProfileItem> profiles, string litePath, string configPath)
    {
        var results = new ConcurrentBag<UrlTestResult>();

        await Parallel.ForEachAsync(profiles, new ParallelOptions { MaxDegreeOfParallelism = _config.MaxThreadCount }, async (profile, ct) =>
        {
            var testResult = await TestProfileWithLite(profile, litePath, configPath);
            if (testResult.Success)
            {
                results.Add(testResult);
            }
        });

        return results;
    }

    private async Task<IReadOnlyCollection<ProfileItem>> CollectProfilesFromConfigSources()
    {
        using var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(8) };
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
            string? line;
            while ((line = reader.ReadLine()?.Trim()) is not null)
            {
                if (_config.IncludedProtocols.Length > 0 &&
                    !_config.IncludedProtocols.Any(proto => line.StartsWith(proto, StringComparison.OrdinalIgnoreCase)))
                    continue;

                yield return new ProfileItem
                {
                    Address = line,
                    Name = string.Empty
                };
            }
        }
    }

    private string ExtractHost(string proxyUrl)
    {
        try
        {
            var atIndex = proxyUrl.IndexOf('@');
            if (atIndex >= 0)
            {
                var rest = proxyUrl.Substring(atIndex + 1);
                var colonIndex = rest.IndexOf(':');
                if (colonIndex > 0)
                    return rest.Substring(0, colonIndex);
                else
                    return rest;
            }
            return proxyUrl;
        }
        catch
        {
            return proxyUrl;
        }
    }
}

// ===== Minimal type definitions =====
public class ProfileItem
{
    public string? Address { get; set; }
    public string? Name { get; set; }
    public string ToProfileUrl() => Address ?? string.Empty;
}

public class UrlTestResult
{
    public ProfileItem Profile { get; set; } = null!;
    public bool Success { get; set; }
    public int Delay { get; set; } // ms
}

// ===== Extension helper =====
public static class HelperExtentions
{
    public static IEnumerable<(int Index, T Item)> WithIndex<T>(this IEnumerable<T> items)
    {
        int index = 0;
        foreach (var item in items)
            yield return (index++, item);
    }
}
