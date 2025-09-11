using MaxMind.GeoIP2;
// using MaxMind.GeoIP2.Responses;
using System.Net;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader _countryReader;
    private readonly DatabaseReader _asnReader;
    private bool _disposed = false;

    public IPToCountryResolver(string geoLiteCountryDbPath, string geoLiteAsnDbPath)
    {
        // Inisialisasi reader GeoLite2
        _countryReader = new DatabaseReader(geoLiteCountryDbPath);
        _asnReader = new DatabaseReader(geoLiteAsnDbPath);
    }

    /// <summary>
    /// Resolve IP atau hostname ke informasi negara dan ISP
    /// </summary>
    public ProxyCountryInfo GetCountry(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            var ips = Dns.GetHostAddresses(address);
            ip = ips[0];
        }

        return GetCountry(ip);
    }

    /// <summary>
    /// Resolve IPAddress ke informasi negara dan ISP
    /// </summary>
    public ProxyCountryInfo GetCountry(IPAddress ip)
    {
        var countryResponse = _countryReader.Country(ip);
        var asnResponse = _asnReader.Asn(ip);

        return new ProxyCountryInfo
        {
            CountryName = countryResponse?.Country?.Name ?? "Unknown",
            CountryCode = countryResponse?.Country?.IsoCode ?? "Unknown",
            Isp = asnResponse?.AutonomousSystemOrganization ?? "Unknown"
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _countryReader.Dispose();
        _asnReader.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Class inner yang menggantikan CountryInfo
    /// </summary>
    public class ProxyCountryInfo
    {
        public string CountryCode { get; set; } = "Unknown";
        public string CountryName { get; set; } = "Unknown";
        public string Isp { get; set; } = "Unknown";
    }
}
