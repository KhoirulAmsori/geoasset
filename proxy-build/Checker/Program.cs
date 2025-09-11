using System.Threading.Tasks;

namespace ProxyChecker;

public static class Program
{
    public static async Task Main()
    {
        var checker = new ProxyChecker();
        await checker.StartAsync();
    }
}
