using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using PostQuantum.FileEncryption.Hybrid;

namespace PostQuantum.FileEncryption.Benchmarks;

/// <summary>
/// End-to-end encrypt/decrypt throughput for the hybrid (X25519 + ML-KEM-768) recipient
/// engine, single- and multi-recipient. The per-recipient KEM cost is a fixed per-file
/// overhead; the data plane is the same chunked AES-256-GCM as the passphrase engine.
/// Decryption uses the <em>last</em> recipient's key so the multi-recipient number shows
/// the worst-case try-each-block cost.
/// </summary>
[MemoryDiagnoser]
[ShortRunJob]
public class HybridThroughputBenchmarks
{
    private byte[] _data = null!;
    private byte[] _container = null!;
    private PqHybridKeyPair[] _keyPairs = null!;
    private PqHybridPublicKey[] _recipients = null!;
    private PqHybridEncryptor _encryptor = null!;
    private PqHybridDecryptor _decryptor = null!;

    /// <summary>Payload size in mebibytes; matches the passphrase suite for comparability.</summary>
    [Params(16)]
    public int Megabytes;

    [Params(1, 10)]
    public int Recipients;

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Megabytes * 1024 * 1024];
        RandomNumberGenerator.Fill(_data);

        _keyPairs = new PqHybridKeyPair[Recipients];
        _recipients = new PqHybridPublicKey[Recipients];
        for (int i = 0; i < Recipients; i++)
        {
            _keyPairs[i] = PqHybridKeyPair.Generate();
            _recipients[i] = _keyPairs[i].PublicKey;
        }

        _encryptor = new PqHybridEncryptor();
        _decryptor = new PqHybridDecryptor();
        _container = _encryptor.EncryptBytesToAsync(_data, _recipients).GetAwaiter().GetResult();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        foreach (var keyPair in _keyPairs)
        {
            keyPair.Dispose();
        }
    }

    [Benchmark]
    public byte[] Encrypt() => _encryptor.EncryptBytesToAsync(_data, _recipients).GetAwaiter().GetResult();

    [Benchmark]
    public byte[] Decrypt() =>
        _decryptor.DecryptBytesAsync(_container, _keyPairs[^1].PrivateKey).GetAwaiter().GetResult();

    [Benchmark]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "BenchmarkDotNet requires benchmark methods to be instance methods.")]
    public void KeyPairGenerate()
    {
        using var keyPair = PqHybridKeyPair.Generate();
    }
}
