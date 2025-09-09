using System.Collections.Concurrent;
using System.Text;
using System.Web;

namespace ProxyCollector.Collector;

public class ProxyCollector
{
    private readonly CollectorConfig _config;

    public ProxyCollector()
    {
        _config = CollectorConfig.Instance;
    }

    private void LogToConsole(string log)
    {
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {log}");
    }

    public async Task StartAsync()
    {
        var startTime = DateTime.Now;
        LogToConsole("Collector started.");

        // 1️⃣ Baca proxy aktif dari Lite output.txt
        if (!File.Exists(_config.LiteOutputPath))
        {
            LogToConsole($"Lite output file not found: {_config.LiteOutputPath}");
            return;
        }

        var lines = await File.ReadAllLinesAsync(_config.LiteOutputPath);
        var activeProfiles = new List<ProfileItem>();
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (!string.IsNullOrEmpty(trimmed))
            {
                activeProfiles.Add(new ProfileItem
                {
                    Address = trimmed,
                    Name = string.Empty
                });
            }
        }

        LogToConsole($"Detected {activeProfiles.Count} active proxies from Lite output.");

        if (activeProfiles.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({activeProfiles.Count}) less than minimum required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        // 2️⃣ Compile results (urutkan saja berdasarkan Address)
        var finalResults = activeProfiles
            .OrderBy(p => p.Address)
            .ToList();

        // 3️⃣ Upload results
        LogToConsole("Uploading results...");
        await CommitResults(finalResults);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task CommitResults(List<ProfileItem> profiles)
    {
        LogToConsole($"Uploading V2ray Subscription...");
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
}

// ===== Minimal type definitions =====
public class ProfileItem
{
    public string? Address { get; set; }
    public string? Name { get; set; }
    public string ToProfileUrl() => Address ?? string.Empty;
}
