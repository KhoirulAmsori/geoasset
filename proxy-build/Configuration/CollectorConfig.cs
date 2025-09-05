namespace ProxyCollector.Configuration;

public class CollectorConfig
{
    public static CollectorConfig Instance { get; private set; }
    public required int MaxProxiesPerCountry { get; init; }
    public required string SingboxPath { get; init; }
    public required string V2rayFormatResultPath { get; init; }
    public required int MaxThreadCount { get; init; }
    public required int Timeout { get; init; }
    public required string[] Sources { get; init; }
    static CollectorConfig()
    {
        Instance = CreateInstance();
    }

    private CollectorConfig() { }

    private static CollectorConfig CreateInstance()
    {
        return new CollectorConfig
        {
            // MaxProxiesPerCountry = int.Parse(Environment.GetEnvironmentVariable("MaxProxiesPerCountry")!),
            MaxProxiesPerCountry = int.TryParse(Environment.GetEnvironmentVariable("MaxProxiesPerCountry"), out var max) ? max : 2, // default 2
            SingboxPath = Environment.GetEnvironmentVariable("SingboxPath")!,
            V2rayFormatResultPath = Environment.GetEnvironmentVariable("V2rayFormatResultPath")!,
            MaxThreadCount = int.Parse(Environment.GetEnvironmentVariable("MaxThreadCount")!),
            Timeout = int.Parse(Environment.GetEnvironmentVariable("Timeout")!),
            Sources = Environment.GetEnvironmentVariable("Sources")!.Split("\n")
        };
    }
}
