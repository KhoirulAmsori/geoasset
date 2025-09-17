namespace ProxyCollector.Configuration;

public class CollectorConfig
{
    public static CollectorConfig Instance { get; private set; }
    public required int MaxProxiesPerCountry { get; init; }
    public required int MaxThreadCount { get; init; }
    public required int MinActiveProxies { get; init; }
    public required int Timeout { get; init; }
    public required string EnableDebug { get; init; }
    public required string GeoLiteAsnDbPath { get; init; }
    public required string GeoLiteCountryDbPath { get; init; }
    public required string LiteConfigPath { get; init; }
    public required string LitePath { get; init; }
    public required string SingboxPath { get; init; }
    public required string V2rayFormatResultPath { get; init; }
    public required string[] IncludedProtocols { get; init; }
    public required string[] Sources { get; init; }

    static CollectorConfig()
    {
        Instance = CreateInstance();
    }

    private CollectorConfig() { }

    private static CollectorConfig CreateInstance()
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

        return new CollectorConfig
        {
            EnableDebug = Environment.GetEnvironmentVariable("EnableDebug")!,
            GeoLiteAsnDbPath = Environment.GetEnvironmentVariable("GeoLiteAsnDbPath")!
            GeoLiteCountryDbPath = Environment.GetEnvironmentVariable("GeoLiteCountryDbPath")!,
            IncludedProtocols = includedProtocols,
            LiteConfigPath = Environment.GetEnvironmentVariable("LiteConfigPath")!,
            LitePath = Environment.GetEnvironmentVariable("LitePath")!,
            MaxProxiesPerCountry = int.Parse(Environment.GetEnvironmentVariable("MaxProxiesPerCountry")!),
            MaxThreadCount = int.Parse(Environment.GetEnvironmentVariable("MaxThreadCount")!),
            MinActiveProxies = int.Parse(Environment.GetEnvironmentVariable("MinActiveProxies")!),
            SingboxPath = Environment.GetEnvironmentVariable("SingboxPath")!,
            Sources = sources,
            Timeout = int.Parse(Environment.GetEnvironmentVariable("Timeout")!),
            V2rayFormatResultPath = Environment.GetEnvironmentVariable("V2rayFormatResultPath")!,
        };
    }
}
