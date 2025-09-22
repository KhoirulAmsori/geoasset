using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using System.Net;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader _countryReader;
    private readonly DatabaseReader _asnReader;
    private bool _disposed = false;

    public IPToCountryResolver(string geoLiteCountryDbPath, string geoLiteAsnDbPath)
    {
        _countryReader = new DatabaseReader(geoLiteCountryDbPath);
        _asnReader = new DatabaseReader(geoLiteAsnDbPath);
    }

    public ProxyCountryInfo GetCountry(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            var ips = Dns.GetHostAddresses(address);
            ip = ips.FirstOrDefault() ?? throw new ArgumentException("Invalid address");
        }

        return GetCountry(ip);
    }

    public ProxyCountryInfo GetCountry(IPAddress ip)
    {
        // Cek apakah IP termasuk reserved/private
        if (IsPrivateOrReserved(ip))
        {
            return new ProxyCountryInfo();
        }

        try
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
        catch (AddressNotFoundException)
        {
            // IP tidak ada di database
            return new ProxyCountryInfo();
        }
        catch (Exception)
        {
            // Error lain (misalnya file DB korup)
            return new ProxyCountryInfo();
        }
    }

    private static bool IsPrivateOrReserved(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        var bytes = ip.GetAddressBytes();

        // IPv4 only (untuk sederhana, bisa diperluas ke IPv6 juga)
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 100.64.0.0/10 (CGNAT)
            if (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127)) return true;
        }

        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _countryReader.Dispose();
        _asnReader.Dispose();
        _disposed = true;
    }

    public class ProxyCountryInfo
    {
        public string CountryCode { get; set; } = "Unknown";
        public string CountryName { get; set; } = "Unknown";
        public string Isp { get; set; } = "Unknown";
    }
}
