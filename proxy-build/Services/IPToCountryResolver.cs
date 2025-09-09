using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Responses;
using Newtonsoft.Json;
using ProxyCollector.Models;
using System.Net;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver
{
    private readonly HttpClient _httpClient;
    private readonly string _geoLiteDbPath;

    public IPToCountryResolver(string geoLiteDbPath)
    {
        _httpClient = new HttpClient();
        _geoLiteDbPath = geoLiteDbPath;
    }

    public async Task<CountryInfo> GetCountry(string address, CancellationToken cancellationToken = default)
    {
        IPAddress? ip = null;
        if (!IPAddress.TryParse(address, out ip))
        {
            var ips = Dns.GetHostAddresses(address);
            ip = ips[0];
        }

        return await GetCountry(ip, cancellationToken);
    }

    public async Task<CountryInfo> GetCountry(IPAddress ip, CancellationToken cancellationToken = default)
    {
        // 1. Coba lookup offline dulu
        var offlineResult = GetCountryOffline(ip);
        if (offlineResult != null)
        {
            return offlineResult;
        }

        // 2. Fallback online
        string? response = null;
        for (int i = 1; i <= 5; i++)
        {
            try
            {
                response = await _httpClient.GetStringAsync($"https://api.iplocation.net/?ip={ip}", cancellationToken);
                break;
            }
            catch (HttpRequestException)
            {
                if (i == 5)
                    throw;
                await Task.Delay(TimeSpan.FromSeconds(20), cancellationToken);
            }
        }

        var ipInfo = JsonConvert.DeserializeObject<IpLocationResponse>(response!)!;

        return new CountryInfo
        {
            CountryName = ipInfo.CountryName,
            CountryCode = ipInfo.CountryCode
        };
    }

    private CountryInfo? GetCountryOffline(IPAddress ip)
    {
        try
        {
            using var reader = new DatabaseReader(_geoLiteDbPath);
            CountryResponse response = reader.Country(ip);

            if (response?.Country?.Name != null && response?.Country?.IsoCode != null)
            {
                return new CountryInfo
                {
                    CountryName = response.Country.Name,
                    CountryCode = response.Country.IsoCode
                };
            }
        }
        catch
        {
            // Ignore errors, fallback ke online
        }
        return null;
    }
}
