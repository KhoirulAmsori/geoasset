using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using ProxyCollector.Models;
using ProxyCollector.Services;
using ProxyCollector.Configuration;
using SingBoxLib.Configuration;
using SingBoxLib.Parsing;
using System.Text.Json;

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
        var finalResults = profiles.ToList();

        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "list.txt");
        var plain = string.Join("\n", finalResults.Select(p => p.ToProfileUrl()));
        await File.WriteAllTextAsync(listPath, plain);
        LogToConsole($"Final list written to {listPath} ({profiles.Count} entries)");

        var liteOk = await RunLiteTest(listPath);
        var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
        if (!liteOk || !File.Exists(outputPath))
        {
            LogToConsole("Lite test failed — skipping upload.");
            await File.WriteAllTextAsync("skip_push.flag", "lite test failed");
            return;
        }

        // --- Proses IPToCountryResolver ---
        LogToConsole("Resolving countries for active proxies...");
        var resolver = new IPToCountryResolver(
            _config.GeoLiteCountryDbPath,    // GeoLite2-Country.mmdb
            _config.GeoLiteAsnDbPath         // GeoLite2-ASN.mmdb
        );
        var lines = await File.ReadAllLinesAsync(outputPath);
        var parsedProfiles = new List<ProfileItem>();
        var countryMap = new Dictionary<ProfileItem, CountryInfo>();

        foreach (var line in lines)
        {
            ProfileItem? profile = null;
            try { profile = ProfileParser.ParseProfileUrl(line); } catch { }
            if (profile == null) continue;

            try
            {
                string? host = profile.Address;

                // Jika kosong, coba decode base64
                if (string.IsNullOrEmpty(host))
                {
                    var decoded = TryBase64Decode(line);

                    if (decoded.StartsWith("{"))
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(decoded);
                            if (doc.RootElement.TryGetProperty("add", out var addProp))
                                host = addProp.GetString();
                        }
                        catch { }
                    }
                }

                if (string.IsNullOrEmpty(host))
                    continue;

                var country = resolver.GetCountry(host);
                countryMap[profile] = country;

                var isp = string.IsNullOrEmpty(country.Isp) ? "UnknownISP" : country.Isp;
                var ispParts = isp.Split(' ', StringSplitOptions.RemoveEmptyEntries);

                var ispTwoWords = ispParts.Length > 1
                    ? string.Join(" ", ispParts.Take(2))
                    : (ispParts.Length == 1 ? ispParts[0] : "UnknownISP");
                var idx = parsedProfiles.Count(p => countryMap.ContainsKey(p) &&
                                                    countryMap[p].CountryCode == country.CountryCode);

                profile.Name = $"{country.CountryCode} {idx + 1} - {ispTwoWords}";
                parsedProfiles.Add(profile);
            }
            catch (Exception ex)
            {
                LogToConsole($"[WARN] Failed resolve {profile.Address}: {ex.Message}");
            }
        }

        var grouped = parsedProfiles
            .GroupBy(p => countryMap[p].CountryCode ?? "ZZ")
            .SelectMany(g => g.Take(_config.MaxProxiesPerCountry))
            .ToList();

        LogToConsole($"Final proxy count after country limit: {grouped.Count}");

        try { File.Delete(listPath); } catch { }
        await File.WriteAllLinesAsync(listPath, grouped.Select(p => p.ToProfileUrl()));
        try { File.Delete(outputPath); } catch { }

        LogToConsole("Uploading results...");
        await CommitResultsFromFile(listPath);

        var timeSpent = DateTime.Now - startTime;
        LogToConsole($"Job finished, time spent: {timeSpent.Minutes:00} minutes and {timeSpent.Seconds:00} seconds.");
    }

    private async Task<bool> RunLiteTest(string listPath)
    {
        try
        {
            var lines = await File.ReadAllLinesAsync(listPath);
            if (lines.Length == 0)
                return false;

            var batchSize = 100; // jumlah proxy per batch
            var batchOutputFiles = new List<string>();
            int batchIndex = 0;

            for (int i = 0; i < lines.Length; i += batchSize)
            {
                var batchLines = lines.Skip(i).Take(batchSize).ToArray();
                var batchFile = Path.Combine(Directory.GetCurrentDirectory(), $"batch_{batchIndex}.txt");
                await File.WriteAllLinesAsync(batchFile, batchLines);

                // jalankan Lite (stdout & stderr dibuang)
                var psi = new ProcessStartInfo
                {
                    FileName = "bash",
                    Arguments = $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} -test '{batchFile}' > /dev/null 2>&1\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = new Process { StartInfo = psi };
                proc.Start();
                await proc.WaitForExitAsync();

                if (proc.ExitCode != 0)
                {
                    LogToConsole($"Warning: Lite batch {batchIndex} finished with exit code {proc.ExitCode}");
                }

                var batchOutput = Path.Combine(Directory.GetCurrentDirectory(), $"output_{batchIndex}.txt");
                if (File.Exists("output.txt"))
                {
                    var linesInBatch = await File.ReadAllLinesAsync("output.txt");
                    var lineCount = linesInBatch.Length;
                    LogToConsole($"Lite batch {batchIndex} produced {lineCount} lines");

                    // rename output.txt Lite menjadi batch output
                    File.Move("output.txt", batchOutput, overwrite: true);
                    batchOutputFiles.Add(batchOutput);
                }
                else
                {
                    LogToConsole($"Warning: Lite batch {batchIndex} did not produce output.txt");
                }

                File.Delete(batchFile); // hapus batch input file
                batchIndex++;
            }

            // gabungkan semua batch output menjadi satu output.txt final
            var finalOutput = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            using var writer = new StreamWriter(finalOutput, false, Encoding.UTF8);

            foreach (var file in batchOutputFiles)
            {
                if (File.Exists(file))
                {
                    var content = await File.ReadAllLinesAsync(file);
                    foreach (var line in content)
                        await writer.WriteLineAsync(line);

                    File.Delete(file); // hapus batch output sementara
                }
            }

            return File.Exists(finalOutput) && new FileInfo(finalOutput).Length > 0;
        }
        catch (Exception ex)
        {
            LogToConsole($"Failed to run Lite test: {ex.Message}");
            return false;
        }
    }

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
                    yield return profile;
            }
        }
    }
}
