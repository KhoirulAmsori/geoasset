using Octokit;
using SingBoxLib.Parsing;
using SingBoxLib.Runtime.Testing;
using SingBoxLib.Runtime;
using SourceChecker.Configuration;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text;

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

    public async Task RunAsync()
    {
        Log("Checker started.");

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var validSources = new List<string>();

        foreach (var source in _config.Sources)
        {
            // --- Ambil & parse profiles ---
            List<ProfileItem> profiles;
            try
            {
                var subContent = await client.GetStringAsync(source);
                profiles = TryParseSubContent(subContent).Distinct().ToList();
            }
            catch (Exception ex)
            {
                Log($"Failed to fetch {source}: {ex.Message}");
                continue;
            }

            if (!profiles.Any())
            {
                Log($"No valid proxies found in source {source}");
                continue;
            }

            // Pisahkan vless dan non-vless
            var vlessProfiles = profiles
                .Where(p => p.ToProfileUrl().StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var liteProfiles = profiles.Except(vlessProfiles).ToList();

            var liteResult = liteProfiles.Any() ? await RunLiteTest(liteProfiles) : new List<ProfileItem>();
            var vlessResult = vlessProfiles.Any() ? await RunSingboxTest(vlessProfiles) : new List<ProfileItem>();

            var activeLite = liteResult.Count;
            var activeSingbox = vlessResult.Count;
            var activeCount = activeLite + activeSingbox;
            var testedProxy = profiles.Count;

            // --- Logging hasil ---
            if (activeCount >= _config.MinActiveProxies)
            {
                Log($"{activeLite.ToString().PadLeft(6)} (NON-VLESS) {activeSingbox.ToString().PadLeft(6)} (VLESS) / {testedProxy.ToString().PadLeft(6)} = {source}");
                validSources.Add(source);
            }
            else
            {
                Log($"{activeCount.ToString().PadLeft(6)} / {testedProxy.ToString().PadLeft(6)} = {source} -> REMOVED!");
            }
        }

        // --- Tulis ulang sources.txt ---
        var sourcesFile = Environment.GetEnvironmentVariable("SourcesFile") ?? "sources.txt";
        File.WriteAllLines(sourcesFile, validSources);

        Log($"Total sources checked : {_config.Sources.Length}");
        Log($"Active sources        : {validSources.Count}");
        Log($"Inactive sources      : {_config.Sources.Length - validSources.Count}");

        await CommitFileToGithub(string.Join(Environment.NewLine, validSources), "proxy-build/Asset/sources.txt");
    }

    // === Helper untuk parsing content (base64 aman) ===
    private IEnumerable<ProfileItem> TryParseSubContent(string subContent)
    {
        try
        {
            var data = Convert.FromBase64String(subContent.Trim());
            subContent = Encoding.UTF8.GetString(data);
        }
        catch
        {
            // bukan base64 → abaikan
        }

        using var reader = new StringReader(subContent);
        string? line;
        while ((line = reader.ReadLine()?.Trim()) is not null)
        {
            if (_config.IncludedProtocols.Length > 0 &&
                !_config.IncludedProtocols.Any(proto => line.StartsWith(proto, StringComparison.OrdinalIgnoreCase)))
                continue;

            ProfileItem? profile = null;
            try { profile = ProfileParser.ParseProfileUrl(line); } catch { }
            if (profile is not null) yield return profile;
        }
    }

    // === Lite test untuk non-vless ===
    private async Task<List<ProfileItem>> RunLiteTest(List<ProfileItem> profiles)
    {
        var listPath = Path.Combine(Directory.GetCurrentDirectory(), "temp_list.txt");
        await File.WriteAllLinesAsync(listPath, profiles.Select(p => p.ToProfileUrl()));

        var jsonPath = Path.Combine(Directory.GetCurrentDirectory(), "out.json");
        if (File.Exists(jsonPath)) 
            File.Delete(jsonPath);

        try
        {
            var debug = string.Equals(_config.EnableDebug, "true", StringComparison.OrdinalIgnoreCase);

            var psi = new ProcessStartInfo
            {
                FileName = "bash",
                Arguments = debug
                    ? $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}'\""
                    : $"-c \"{_config.LitePath} --config {_config.LiteConfigPath} --test '{listPath}' > /dev/null 2>&1\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = new Process { StartInfo = psi };
            proc.Start();
            await proc.WaitForExitAsync();

            if (!File.Exists(jsonPath)) return new List<ProfileItem>();

            using var doc = JsonDocument.Parse(File.ReadAllText(jsonPath));
            var nodes = doc.RootElement.GetProperty("nodes");
            var result = new List<ProfileItem>();

            foreach (var node in nodes.EnumerateArray())
            {
                if (node.TryGetProperty("isok", out var isokProp) &&
                    isokProp.ValueKind == JsonValueKind.True &&
                    node.TryGetProperty("link", out var linkProp))
                {
                    var profile = ProfileParser.ParseProfileUrl(linkProp.GetString()!);
                    if (profile != null) result.Add(profile);
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            Log($"Lite test failed: {ex.Message}");
            return new List<ProfileItem>();
        }
    }

    // === SingBox test untuk vless ===
    private async Task<List<ProfileItem>> RunSingboxTest(List<ProfileItem> profiles)
    {
        if (!profiles.Any()) return new List<ProfileItem>();

        var tester = new ParallelUrlTester(
            new SingBoxWrapper(_config.SingboxPath),
            20000,
            _config.MaxThreadCount,
            _config.Timeout,
            1024,
            "http://www.gstatic.com/generate_204"
        );

        var workingResults = new ConcurrentBag<UrlTestResult>();
        await tester.ParallelTestAsync(profiles, new Progress<UrlTestResult>(r =>
        {
            if (r.Success) workingResults.Add(r);
        }), default);

        return workingResults.Select(r => r.Profile).ToList();
    }

    // === Commit hasil ke Github ===
    private async Task CommitFileToGithub(string content, string path)
    {
        string? sha = null;
        string? existingContent = null;

        var client = new GitHubClient(new ProductHeaderValue("SourceChecker"))
        {
            Credentials = new Credentials(_config.GithubApiToken)
        };

        try
        {
            var contents = await client.Repository.Content.GetAllContents(_config.GithubUser, _config.GithubRepo, path);
            var file = contents.FirstOrDefault();
            sha = file?.Sha;
            existingContent = file?.Content;
        }
        catch
        {
            // file belum ada → abaikan
        }

        if (sha is null)
        {
            await client.Repository.Content.CreateFile(
                _config.GithubUser,
                _config.GithubRepo,
                path,
                new CreateFileRequest("Add sources file.", content)
            );
            Log("Sources file did not exist, created a new file.");
        }
        else
        {
            if (existingContent?.Trim() == content.Trim())
            {
                Log("No changes in sources file, skipping commit.");
                return;
            }

            await client.Repository.Content.UpdateFile(
                _config.GithubUser,
                _config.GithubRepo,
                path,
                new UpdateFileRequest("Update active sources.", content, sha)
            );
            Log("Sources file updated successfully.");
        }
    }
}
