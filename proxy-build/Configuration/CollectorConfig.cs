namespace ProxyCollector.Configuration;

public class CollectorConfig
{
    public static CollectorConfig Instance { get; private set; }
    public required int MaxProxiesPerCountry { get; init; }
    public required int MinActiveProxies { get; init; }
    public required int maxRetriesCount { get; init; }
    public required string SingboxPath { get; init; }
    public required string V2rayFormatResultPath { get; init; }
    public required int MaxThreadCount { get; init; }
    public required int Timeout { get; init; }
    public required string[] Sources { get; init; }
    // Tambahkan property SkipProtocols
    public required string[] SkipProtocols { get; init; }

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

        // Ambil skip protocols dari ENV, default kosong
        var skipProtocols = (Environment.GetEnvironmentVariable("SkipProtocols") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.EndsWith("://") ? p : $"{p}://")
            .ToArray();

        return new CollectorConfig
        {
            MaxProxiesPerCountry = int.Parse(Environment.GetEnvironmentVariable("MaxProxiesPerCountry")!),
            MinActiveProxies = int.Parse(Environment.GetEnvironmentVariable("MinActiveProxies")!),
            maxRetriesCount = int.Parse(Environment.GetEnvironmentVariable("maxRetries")!),
            SingboxPath = Environment.GetEnvironmentVariable("SingboxPath")!,
            V2rayFormatResultPath = Environment.GetEnvironmentVariable("V2rayFormatResultPath")!,
            MaxThreadCount = int.Parse(Environment.GetEnvironmentVariable("MaxThreadCount")!),
            Timeout = int.Parse(Environment.GetEnvironmentVariable("Timeout")!),
            Sources = sources,
            SkipProtocols = skipProtocols
        };
    }
}
