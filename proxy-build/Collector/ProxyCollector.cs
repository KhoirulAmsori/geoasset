using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

using ProxyCollector.Configuration;
using SingBoxLib.Configuration;
using SingBoxLib.Parsing;

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
            .ToList();

        // tulis list.txt => namun lite mengharapkan base64 subscription, jadi encode dulu
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        var plain = string.Join("\n", finalResults.Select(p => p.ToProfileUrl()));
        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
        await File.WriteAllTextAsync(listPath, base64);
        LogToConsole($"Temporary list written to {listPath} (base64-encoded, {finalResults.Count} entries)");

        // jalankan lite test
        var liteOk = await RunLiteTest(listPath);

        if (!liteOk)
        {
            LogToConsole("Lite test failed — skipping upload.");
            await File.WriteAllTextAsync("skip_push.flag", "lite test failed");
            return;
        }

        // jika sukses, RunLiteTest sudah mengganti output.txt -> list.txt (overwrite)
        LogToConsole("Uploading results...");
        await CommitResultsFromFile(listPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    /// <summary>
    /// Jalankan lite --config config.json -test list.txt
    /// Jika sukses (exit code 0) dan output.txt ada, rename output.txt -> list.txt (overwrite).
    /// Kembalikan true jika rename berhasil.
    /// </summary>
    private async Task<bool> RunLiteTest(string listPath)
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

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            if (proc.ExitCode == 0 && File.Exists(outputPath))
            {
                // replace original list.txt with output.txt
                try
                {
                    File.Delete(listPath); // hapus base64 input
                }
                catch { /* ignore */ }

                File.Move(outputPath, listPath); // rename output.txt -> list.txt
                LogToConsole($"Renamed {outputPath} -> {listPath}");
                return true;
            }
            else
            {
                LogToConsole("Warning: lite did not produce a valid output.txt or exited with error.");
                if (File.Exists(outputPath))
                    LogToConsole($"Note: output.txt exists but lite exit code = {proc.ExitCode}.");
                return false;
            }
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to run lite test: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Commit / upload berdasarkan file list.txt yang dihasilkan lite (sudah berisi daftar final).
    /// </summary>
    private async Task CommitResultsFromFile(string listPath)
    {
        LogToConsole("Uploading V2ray Subscription...");

        if (!File.Exists(listPath))
        {
            LogToConsole("list.txt not found, skipping upload.");
            return;
        }

        var outputPath = _config.V2rayFormatResultPath;
        var dir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        File.Copy(listPath, outputPath, true);
        LogToConsole($"Subscription file written to {outputPath}");

        await Task.CompletedTask;
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
