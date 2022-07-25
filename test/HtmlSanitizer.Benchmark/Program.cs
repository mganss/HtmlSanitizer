using BenchmarkDotNet.Running;
using Ganss.Xss.Benchmark;

BenchmarkSwitcher.FromAssembly(typeof(HtmlSanitizerBenchmark).Assembly).Run(args);