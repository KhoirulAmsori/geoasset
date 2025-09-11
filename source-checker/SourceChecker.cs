using Octokit;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using SourceChecker.Configuration;
using SingBoxLib.Parsing;
using System.Text.Json;

namespace SourceChecker;

public class SourceChecker
{
    private readonly Config _config;

    public SourceChecker()
    {
        _config = Config.Instance;
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
        if (string.IsNullOrWhiteSpace(input)) return input;

        // Buang whitespace & newline supaya bisa diparse
        var compact = input.Trim().Replace("\r", "").Replace("\n", "");

        try
        {
            // Base64 decode
            var bytes = Convert.FromBase64String(compact);
            var decoded = Encoding.UTF8.GetString(bytes);

            // Kalau hasil decode ternyata masih berisi URL schema (vmess://, ss://, trojan://, vless://, hysteria2://, dll)
            if (decoded.Contains("://"))
                return decoded;
        }
        catch
        {
            // Bukan base64 valid → kembalikan input asli
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
        var validSources = new List<string>();
        int totalActiveProxies = 0;
        int totalTestedProxies = 0;

        foreach (var source in _config.Sources)
        {
            string content;
            try
            {
                content = await client.GetStringAsync(source);
                content = content.Trim();
                content = TryBase64Decode(content);
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

            // Hapus out.json lama
            var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
            if (File.Exists(jsonPath)) File.Delete(jsonPath);

            var liteJson = await RunLite(tempListPath);
            if (liteJson == null)
            {
                Log($"Lite test failed for source {source}");
                continue;
            }

            var (activeCount, testedProxy) = CountProxies(liteJson);
            
            if (activeCount >= 2)
            {
                Log($"{activeCount.ToString().PadLeft(4)} / {testedProxy.ToString().PadLeft(6)} = {source}");
                validSources.Add(source);
                totalActiveProxies += activeCount;
                totalTestedProxies += testedProxy;
            }
            else
            {
                Log($"{activeCount.ToString().PadLeft(4)} / {testedProxy.ToString().PadLeft(6)} = {source} -> REMOVED!");
            }
        }

        // Tulis ulang sources.txt hanya dengan link valid
        var sourcesFile = Environment.GetEnvironmentVariable("SourcesFile") ?? "sources.txt";
        File.WriteAllLines(sourcesFile, validSources);

        var included = _config.IncludedProtocols.Length > 0
            ? string.Join(", ", _config.IncludedProtocols.Select(p => p.Replace("://", "").ToUpperInvariant()))
            : "all";

        Log($"Total sources checked: {_config.Sources.Length}");
        Log($"Active sources: {validSources.Count}");
        Log($"Inactive sources: {_config.Sources.Length - validSources.Count}");
        Log($"Summary: {totalActiveProxies} active proxies from {totalTestedProxies} tested proxy with protocols: {included}.");

        //await CommitFileToGithub(string.Join(Environment.NewLine, validSources), "proxy-build/Asset/sources.txt");
    }

    private (int Active, int Tested) CountActiveProxies(string jsonPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
        var nodes = doc.RootElement.GetProperty("nodes");

        int active = 0;
        int tested = nodes.GetArrayLength();

        foreach (var node in nodes.EnumerateArray())
        {
            if (node.TryGetProperty("isok", out var isokProp) &&
                isokProp.ValueKind == JsonValueKind.True)
            {
                active++;
            }
        }

        return (active, tested);
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

    private async Task CommitFileToGithub(string content, string path)
    {
        string? sha = null;
        string? existingContent = null;

        var client = new GitHubClient(new ProductHeaderValue("ProxyCollector"))
        {
            Credentials = new Credentials(_config.GithubApiToken)
        };

        try
        {
            var contents = await client.Repository.Content.GetAllContents(_config.GithubUser, _config.GithubRepo, path);
            var file = contents.FirstOrDefault();
            sha = file?.Sha;
            existingContent = file?.Content; // ambil isi file lama
        }
        catch 
        {
            // file belum ada → abaikan error
        }

        if (sha is null)
        {
            // file belum ada → buat baru
            await client.Repository
                .Content
                .CreateFile(_config.GithubUser, _config.GithubRepo, path,
                new CreateFileRequest("Add sources file.", content));
            Log("Sources file did not exist, created a new file.");
        }
        else
        {
            // cek apakah ada perubahan konten
            if (existingContent?.Trim() == content.Trim())
            {
                Log("No changes in sources file, skipping commit.");
                return;
            }

            // kalau ada perubahan → update
            await client.Repository
                .Content
                .UpdateFile(_config.GithubUser, _config.GithubRepo, path,
                new UpdateFileRequest("Update active sources.", content, sha));
            Log("Sources file updated successfully.");
        }
    }
}
