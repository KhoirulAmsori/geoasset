using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;
using ProxyCollector.Models;
using System.Net;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader _countryReader;
    private readonly DatabaseReader _asnReader;
    private bool _disposed = false;

    public IPToCountryResolver(string geoLiteCountryDbPath, string geoLiteAsnDbPath)
    {
        // Buka reader sekali untuk batch lookup
        _countryReader = new DatabaseReader(geoLiteCountryDbPath);
        _asnReader = new DatabaseReader(geoLiteAsnDbPath);
    }

    public CountryInfo GetCountry(string address)
    {
        IPAddress? ip = null;
        if (!IPAddress.TryParse(address, out ip))
        {
            var ips = Dns.GetHostAddresses(address);
            ip = ips[0];
        }

        return GetCountry(ip!);
    }

    public CountryInfo GetCountry(IPAddress ip)
    {
        string countryName = "Unknown";
        string countryCode = "Unknown";
        string isp = "Unknown";

        // Lookup Country
        var countryResponse = _countryReader.Country(ip);
        countryName = countryResponse?.Country?.Name ?? "Unknown";
        countryCode = countryResponse?.Country?.IsoCode ?? "Unknown";

        // Lookup ASN / ISP
        var asnResponse = _asnReader.Asn(ip);
        isp = asnResponse?.AutonomousSystemOrganization ?? "Unknown";

        return new CountryInfo
        {
            CountryName = countryName,
            CountryCode = countryCode,
            Isp = isp
        };
    }

    // IDisposable pattern untuk menutup reader saat selesai
    public void Dispose()
    {
        if (_disposed) return;
        _countryReader.Dispose();
        _asnReader.Dispose();
        _disposed = true;
    }
}
