using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using ProxyCollector.Configuration;
using SingBoxLib.Parsing;
using System.Text.Json;

namespace ProxyCheckerApp;

public class ProxyChecker
{
    private readonly CollectorConfig _config;

    public ProxyChecker()
    {
        _config = CollectorConfig.Instance;
    }

    private void Log(string message) =>
        Console.WriteLine($"{DateTime.Now:HH:mm:ss} - {message}");

    private static bool LooksLikeBase64(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        s = s.Trim();
        return s.Length % 4 == 0 && s.All(c => char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=');
    }

    private static string TryBase64Decode(string input)
    {
        if (LooksLikeBase64(input))
        {
            try
            {
                int mod4 = input.Length % 4;
                if (mod4 > 0) input = input.PadRight(input.Length + (4 - mod4), '=');
                return Encoding.UTF8.GetString(Convert.FromBase64String(input));
            }
            catch { }
        }
        return input;
    }

    private List<ProfileItem> ParseProfiles(string content)
    {
        var profiles = new List<ProfileItem>();
        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()?.Trim()) != null)
        {
            if (_config.IncludedProtocols.Length > 0 &&
                !_config.IncludedProtocols.Any(proto => line.StartsWith(proto, StringComparison.OrdinalIgnoreCase)))
                continue;

            try
            {
                var profile = ProfileParser.ParseProfileUrl(line);
                if (profile != null) profiles.Add(profile);
            }
            catch { }
        }
        return profiles;
    }

    public async Task RunAsync()
    {
        Log("Checker started.");

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        foreach (var source in _config.Sources)
        {
            string content;
            try
            {
                content = await client.GetStringAsync(source);
                content = content.Trim();
                if (LooksLikeBase64(content))
                    content = Encoding.UTF8.GetString(Convert.FromBase64String(content));
            }
            catch (Exception ex)
            {
                Log($"Failed to fetch {source}: {ex.Message}");
                continue;
            }

            var profiles = ParseProfiles(content);
            if (!profiles.Any())
            {
                Log($"No valid proxies found in source {source}");
                continue;
            }

            var tempListPath = Path.Combine(Directory.GetCurrentDirectory(), "temp_list.txt");
            await File.WriteAllLinesAsync(tempListPath, profiles.Select(p => p.ToProfileUrl()));

            // Hapus out.json lama sebelum Lite
            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (File.Exists(jsonPath)) File.Delete(jsonPath);

            var liteJson = await RunLite(tempListPath);
            if (liteJson == null)
            {
                Log($"Lite test failed for source {source}");
                continue;
            }

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "output.txt");
            SaveActiveLinksToFile(liteJson, outputPath);

            var activeCount = File.Exists(outputPath) ? File.ReadAllLines(outputPath).Length : 0;
            Log($"Source {source} has {activeCount} active proxies");
        }

        Log("All sources processed.");
    }

    private void SaveActiveLinksToFile(string jsonPath, string outputPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
        var nodes = doc.RootElement.GetProperty("nodes");
        var result = new List<(string Link, int Ping)>();

        foreach (var node in nodes.EnumerateArray())
        {
            if (node.TryGetProperty("isok", out var isokProp) &&
                isokProp.ValueKind == JsonValueKind.True &&
                node.TryGetProperty("ping", out var pingProp))
            {
                var pingStr = pingProp.GetString();
                if (int.TryParse(pingStr, out int ping) && ping > 0)
                {
                    if (node.TryGetProperty("link", out var linkProp))
                    {
                        var link = linkProp.GetString();
                        if (!string.IsNullOrEmpty(link))
                            result.Add((link, ping));
                    }
                }
            }
        }

        var ordered = result.OrderBy(r => r.Ping).Select(r => r.Link).ToList();
        File.WriteAllLines(outputPath, ordered);
    }

    private async Task<string?> RunLite(string listPath)
    {
        try
        {
            var debug = string.Equals(_config.EnableDebug, "true", StringComparison.OrdinalIgnoreCase);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "bash",
                Arguments = debug
                    ? $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}'\""
                    : $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}' > /dev/null 2>&1\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new System.Diagnostics.Process { StartInfo = psi };
            proc.Start();
            await proc.WaitForExitAsync();

            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (proc.ExitCode == 0 && File.Exists(jsonPath))
                return jsonPath;

            Log($"Lite test failed with exit code {proc.ExitCode}");
            return null;
        }
        catch (Exception ex)
        {
            Log($"Failed to run Lite test: {ex.Message}");
            return null;
        }
    }
}
