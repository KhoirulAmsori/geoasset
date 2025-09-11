using System.Threading.Tasks;

class Program
{
    static async Task Main()
    {
        var checker = new ProxyCheckerApp.ProxyChecker();
        await checker.RunAsync();
    }
}
