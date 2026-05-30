using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using PostQuantum.FileEncryption;

namespace PostQuantum.FileEncryption.Benchmarks;

/// <summary>
/// End-to-end encrypt/decrypt throughput for the symmetric engine, including one passphrase
/// key derivation per operation (a fixed per-file cost). Run with:
/// <c>dotnet run -c Release --project benchmarks/PostQuantum.FileEncryption.Benchmarks</c>.
/// </summary>
[MemoryDiagnoser]
[ShortRunJob]
public class ThroughputBenchmarks
{
    private const string Passphrase = "benchmark-passphrase";

    private byte[] _data = null!;
    private byte[] _container = null!;
    private PqFileEncryptor _encryptor = null!;
    private PqFileDecryptor _decryptor = null!;

    /// <summary>Payload size in mebibytes; large enough to amortize the one-time KDF cost.</summary>
    [Params(16)]
    public int Megabytes;

    [Params(PqKdf.Pbkdf2HmacSha256, PqKdf.Argon2id)]
    public PqKdf Kdf;

    [GlobalSetup]
    public void Setup()
    {
        _data = new byte[Megabytes * 1024 * 1024];
        RandomNumberGenerator.Fill(_data);

        // Modest KDF cost so the benchmark reflects data throughput, not KDF tuning.
        var options = new PqEncryptionOptions
        {
            Kdf = Kdf,
            Pbkdf2Iterations = 100_000,
            Argon2MemoryKiB = 8 * 1024,
            Argon2Iterations = 1,
            Argon2Parallelism = 1,
        };
        _encryptor = new PqFileEncryptor(options);
        _decryptor = new PqFileDecryptor();
        _container = _encryptor.EncryptBytesAsync(_data, Passphrase).GetAwaiter().GetResult();
    }

    [Benchmark]
    public byte[] Encrypt() => _encryptor.EncryptBytesAsync(_data, Passphrase).GetAwaiter().GetResult();

    [Benchmark]
    public byte[] Decrypt() => _decryptor.DecryptBytesAsync(_container, Passphrase).GetAwaiter().GetResult();
}
