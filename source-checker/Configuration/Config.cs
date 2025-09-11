namespace SourceChecker.Configuration;

public class Config
{
    public static Config Instance { get; private set; }
    
    public required string GithubApiToken { get; init; }
    public required string GithubUser { get; init; }
    public required string GithubRepo { get; init; }
    public required string EnableDebug { get; init; }
    public required string LitePath { get; init; }
    public required string LiteConfigPath { get; init; }
    public required string[] Sources { get; init; }
    public required string[] IncludedProtocols { get; init; }

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
            GithubApiToken = Environment.GetEnvironmentVariable("GithubApiToken")!,
            GithubUser = Environment.GetEnvironmentVariable("GithubUser")!,
            GithubRepo = Environment.GetEnvironmentVariable("GithubRepo")!,
            EnableDebug = Environment.GetEnvironmentVariable("EnableDebug")!,
            LitePath = Environment.GetEnvironmentVariable("LitePath")!,
            LiteConfigPath = Environment.GetEnvironmentVariable("LiteConfigPath")!,
            Sources = sources,
            IncludedProtocols = includedProtocols
        };
    }
}
