using BenchmarkDotNet.Running;

namespace Ganss.XSS.Benchmark
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            BenchmarkSwitcher.FromAssembly(typeof(HtmlSanitizerBenchmark).Assembly).Run(args);
        }
    }
}