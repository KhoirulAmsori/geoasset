namespace ProxyCollector.Configuration;

public class CollectorConfig
{
    public static CollectorConfig Instance { get; private set; }
    public required int MaxProxiesPerCountry { get; init; }
    public required int MinActiveProxies { get; init; }
    public required int maxRetriesCount { get; init; }
    public required string LitePath { get; init; }
    public required string LiteConfigPath { get; init; }
    public required string V2rayFormatResultPath { get; init; }
    public required int MaxThreadCount { get; init; }
    public required int Timeout { get; init; }
    public required string[] Sources { get; init; }
    public required string[] IncludedProtocols { get; init; }
    public required string[] TestUrls { get; init; }

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

        // Ambil TestUrls dari env
        var testUrlsEnv = Environment.GetEnvironmentVariable("TestUrls") ?? "";
        var testUrls = testUrlsEnv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);


        return new CollectorConfig
        {
            MaxProxiesPerCountry = int.Parse(Environment.GetEnvironmentVariable("MaxProxiesPerCountry")!),
            MinActiveProxies = int.Parse(Environment.GetEnvironmentVariable("MinActiveProxies")!),
            maxRetriesCount = int.Parse(Environment.GetEnvironmentVariable("maxRetries")!),
            LitePath = Environment.GetEnvironmentVariable("LitePath")!,
            LiteConfigPath = Environment.GetEnvironmentVariable("LiteConfigPath")!,
            V2rayFormatResultPath = Environment.GetEnvironmentVariable("V2rayFormatResultPath")!,
            MaxThreadCount = int.Parse(Environment.GetEnvironmentVariable("MaxThreadCount")!),
            Timeout = int.Parse(Environment.GetEnvironmentVariable("Timeout")!),
            Sources = sources,
            IncludedProtocols = includedProtocols,
            TestUrls = testUrls.Length > 0 
                        ? testUrls 
                        : new[] { "https://www.gstatic.com/generate_204", "http://cp.cloudflare.com" }
        };
    }
}
