using System.Threading.Tasks;

namespace SourceChecker;

public static class Program
{
    public static async Task Main()
    {
        var checker = new SourceChecker();
        await checker.StartAsync();
    }
}
