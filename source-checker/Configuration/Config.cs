namespace SourceChecker.Configuration;

public class Config
{
    public static Config Instance { get; private set; }
    public required int MaxThreadCount { get; init; }
    public required int MinActiveProxies { get; init; }
    public required int Timeout { get; init; }
    public required string EnableDebug { get; init; }
    public required string GithubApiToken { get; init; }
    public required string GithubRepo { get; init; }
    public required string GithubUser { get; init; }
    public required string LiteConfigPath { get; init; }
    public required string LitePath { get; init; }
    public required string SingboxPath { get; init; }
    public required string[] IncludedProtocols { get; init; }
    public required string[] Sources { get; init; }

    static Config() => Instance = CreateInstance();

    private static Config CreateInstance()
    {
        var sourcesFile = Environment.GetEnvironmentVariable("SourcesFile") ?? "sources.txt";

        string[] sources = Array.Empty<string>();
        if (File.Exists(sourcesFile))
        {
            sources = File.ReadAllLines(sourcesFile)
                          .Select(line => line.Trim())
                          .Where(line => !string.IsNullOrWhiteSpace(line))
                          .ToArray();
        }

        var includedProtocols = (Environment.GetEnvironmentVariable("IncludedProtocols") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.EndsWith("://") ? p : $"{p}://")
            .ToArray();

        return new Config
        {
            EnableDebug = Environment.GetEnvironmentVariable("EnableDebug")!,
            GithubApiToken = Environment.GetEnvironmentVariable("GithubApiToken")!,
            GithubRepo = Environment.GetEnvironmentVariable("GithubRepo")!,
            GithubUser = Environment.GetEnvironmentVariable("GithubUser")!,
            IncludedProtocols = includedProtocols,
            LiteConfigPath = Environment.GetEnvironmentVariable("LiteConfigPath")!,
            LitePath = Environment.GetEnvironmentVariable("LitePath")!,
            MaxThreadCount = int.Parse(Environment.GetEnvironmentVariable("MaxThreadCount")!),
            MinActiveProxies = int.Parse(Environment.GetEnvironmentVariable("MinActiveProxies")!),
            SingboxPath = Environment.GetEnvironmentVariable("SingboxPath")!,
            Sources = sources,
            Timeout = int.Parse(Environment.GetEnvironmentVariable("Timeout")!)
        };
    }
}
