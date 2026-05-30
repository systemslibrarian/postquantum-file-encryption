using BenchmarkDotNet.Running;
using PostQuantum.FileEncryption.Benchmarks;

BenchmarkSwitcher.FromTypes(new[] { typeof(ThroughputBenchmarks) }).Run(args);
