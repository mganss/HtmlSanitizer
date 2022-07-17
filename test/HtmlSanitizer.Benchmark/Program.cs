using BenchmarkDotNet.Running;
using Ganss.XSS.Benchmark;

BenchmarkSwitcher.FromAssembly(typeof(HtmlSanitizerBenchmark).Assembly).Run(args);