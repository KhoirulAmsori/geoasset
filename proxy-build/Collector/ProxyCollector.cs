using ProxyCollector.Configuration;
using SingBoxLib.Parsing;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;

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

        var profiles = (await CollectProfilesFromConfigSources()).Distinct().ToList();
        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        LogToConsole($"Collected {profiles.Count} unique profiles with protocols: {included}.");
        LogToConsole($"Minimum active proxies >= {_config.MinActiveProxies}.");

        if (profiles.Count < _config.MinActiveProxies)
        {
            LogToConsole($"Active proxies ({profiles.Count}) less than required ({_config.MinActiveProxies}). Skipping push.");
            await File.WriteAllTextAsync("skip_push.flag", "not enough proxies");
            return;
        }

        LogToConsole("Compiling results...");
        var finalResults = profiles
            .Take(_config.MaxProxiesPerCountry) // ambil sesuai batas
            .ToList();

        // === tulis list.txt untuk dites dengan Lite ===
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        await File.WriteAllLinesAsync(listPath, finalResults.Select(p => p.ToProfileUrl()));
        LogToConsole($"Temporary list written to {listPath}");

        // === jalankan perintah lite test ===
        await RunLiteTest(listPath);

        LogToConsole("Uploading results...");
        await CommitResults(finalResults);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task RunLiteTest(string listPath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _config.LitePath,
                Arguments = $"--config {_config.LiteConfigPath} -test \"{listPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };
            proc.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) LogToConsole(e.Data); };
            proc.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) LogToConsole("[ERR] " + e.Data); };

            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            await proc.WaitForExitAsync();

            LogToConsole($"Lite test finished with exit code {proc.ExitCode}");

            // === rename output.txt -> list.txt ===
            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            if (File.Exists(outputPath))
            {
                File.Delete(listPath); // hapus list.txt lama
                File.Move(outputPath, listPath);
                LogToConsole($"Renamed {outputPath} -> {listPath}");
            }
            else
            {
                LogToConsole("Warning: output.txt not found after lite test!");
            }
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to run lite test: {ex.Message}");
        }
    }

    private async Task CommitResults(List<ProfileItem> profiles)
    {
        LogToConsole("Uploading V2ray Subscription...");
        await CommitV2raySubscriptionResult(profiles);
    }

    private async Task CommitV2raySubscriptionResult(List<ProfileItem> profiles)
    {
        var finalResult = new StringBuilder();
        foreach (var profile in profiles)
        {
            finalResult.AppendLine(profile.ToProfileUrl());
        }

        var outputPath = _config.V2rayFormatResultPath;

        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        await File.WriteAllTextAsync(outputPath, finalResult.ToString());
        LogToConsole($"Subscription file written to {outputPath}");
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
