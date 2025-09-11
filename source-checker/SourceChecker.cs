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

            var activeCount = CountActiveProxies(liteJson);
            if (activeCount > 0)
            {
                Log($"{source} has {activeCount} active proxies");
                validSources.Add(source);
            }
            else
            {
                Log($"{source} has no active proxies -> removed");
            }
        }

        // Tulis ulang sources.txt hanya dengan link valid
        var sourcesFile = Environment.GetEnvironmentVariable("SourcesFile") ?? "sources.txt";
        File.WriteAllLines(sourcesFile, validSources);

        Log($"Total sources checked: {_config.Sources.Length}");
        Log($"Active sources: {validSources.Count}");
        Log($"Inactive sources: {_config.Sources.Length - validSources.Count}");

        await UploadActiveSourcesAsync(validSources);
    }

    private int CountActiveProxies(string jsonPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
        var nodes = doc.RootElement.GetProperty("nodes");
        int count = 0;

        foreach (var node in nodes.EnumerateArray())
        {
            if (node.TryGetProperty("isok", out var isokProp) &&
                isokProp.ValueKind == JsonValueKind.True)
            {
                count++;
            }
        }

        return count;
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
    
    private async Task UploadActiveSourcesAsync(List<string> validSources)
    {
        try
        {
        var token = _config.GithubApiToken;
        var user = _config.GithubUser;
        var repo = _config.GithubRepo;

        var github = new GitHubClient(new ProductHeaderValue("SourceChecker"))
        {
            Credentials = new Credentials(token)
        };

        // path di repo tempat overwrite
        var path = "proxy-build/Asset/sources.txt";

        // isi file (gabungkan dengan newline)
        var newContent = string.Join("\n", validSources);

        // cek apakah file sudah ada
        RepositoryContentsResponse existing;
        try
        {
            existing = await github.Repository.Content.GetAllContentsByRef(user, repo, path, "dev");
        }
        catch (NotFoundException)
        {
            existing = null!;
        }

        if (existing != null && existing.Any())
        {
            // update file lama
            var update = new UpdateFileRequest(
                "Update sources file.",
                newContent,
                existing.First().Sha,
                branch: "dev"
            );

            await github.Repository.Content.UpdateFile(user, repo, path, update);
        }
        else
        {
            // buat file baru
            var create = new CreateFileRequest(
                "Add sources file.",
                newContent,
                branch: "dev"
            );

            await github.Repository.Content.CreateFile(user, repo, path, create);
        }

        Log("Commit active sources to GitHub.");
    }
    catch (Exception ex)
    {
        Log($"Failed to upload active sources: {ex.Message}");
    }
}
}
