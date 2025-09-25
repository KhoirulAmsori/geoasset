using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader _countryReader;
    private readonly DatabaseReader _asnReader;
    private readonly SemaphoreSlim _dnsSemaphore;
    private readonly ConcurrentDictionary<string, IPAddress?> _dnsCache = new();
    private bool _disposed = false;

    public IPToCountryResolver(string geoLiteCountryDbPath, string geoLiteAsnDbPath, int maxConcurrentDns = 20)
    {
        _countryReader = new DatabaseReader(geoLiteCountryDbPath);
        _asnReader = new DatabaseReader(geoLiteAsnDbPath);
        _dnsSemaphore = new SemaphoreSlim(maxConcurrentDns, maxConcurrentDns);
    }

    public ProxyCountryInfo GetCountry(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            // gunakan cache agar tidak resolve berulang
            ip = _dnsCache.GetOrAdd(address, host =>
            {
                try
                {
                    _dnsSemaphore.Wait();
                    var ips = Dns.GetHostAddresses(host)
                        .Where(x => x.AddressFamily == AddressFamily.InterNetwork) // IPv4 only
                        .ToArray();
                    return ips.FirstOrDefault();
                }
                catch
                {
                    return null;
                }
                finally
                {
                    _dnsSemaphore.Release();
                }
            });

            if (ip == null)
                return new ProxyCountryInfo();
        }

        return GetCountry(ip);
    }

    public ProxyCountryInfo GetCountry(IPAddress ip)
    {
        if (IsPrivateOrReserved(ip))
            return new ProxyCountryInfo();

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
            return new ProxyCountryInfo();
        }
        catch
        {
            return new ProxyCountryInfo();
        }
    }

    private static bool IsPrivateOrReserved(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return true; // skip IPv6

        var bytes = ip.GetAddressBytes();

        // 10.0.0.0/8
        if (bytes[0] == 10) return true;
        // 172.16.0.0/12
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
        // 192.168.0.0/16
        if (bytes[0] == 192 && bytes[1] == 168) return true;
        // 100.64.0.0/10 (CGNAT)
        if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return true;

        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _countryReader.Dispose();
        _asnReader.Dispose();
        _dnsSemaphore.Dispose();
        _disposed = true;
    }

    public class ProxyCountryInfo
    {
        public string CountryCode { get; set; } = "Unknown";
        public string CountryName { get; set; } = "Unknown";
        public string Isp { get; set; } = "Unknown";
    }
}
