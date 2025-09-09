using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;
using ProxyCollector.Models;
using System.Net;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver
{
    private readonly string _geoLiteDbPath;

    public IPToCountryResolver(string geoLiteDbPath)
    {
        _geoLiteDbPath = geoLiteDbPath;
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
        using var reader = new DatabaseReader(_geoLiteDbPath);
        var response = reader.Country(ip);

        return new CountryInfo
        {
            CountryName = response?.Country?.Name ?? "Unknown",
            CountryCode = response?.Country?.IsoCode ?? "Unknown"
        };
    }
}
