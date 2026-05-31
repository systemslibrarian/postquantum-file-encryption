namespace PostQuantum.FileEncryption;

/// <summary>
/// Configuration for <see cref="PqFileEncryptor"/>. Every value has a strong, modern
/// default — you only need to supply options when you have a specific reason to deviate.
/// </summary>
/// <remarks>
/// Options affect how new ciphertext is <em>produced</em>. Decryption always reads its
/// parameters (KDF, iteration/memory cost, salt, chunk size) from the container header, so a
/// file encrypted with one set of options decrypts correctly regardless of the decryptor's
/// options.
/// </remarks>
public sealed class PqEncryptionOptions
{
    /// <summary>
    /// The key-derivation function used for passphrase-based encryption. Defaults to
    /// <see cref="PqKdf.Pbkdf2HmacSha256"/> (no extra dependency). Choose
    /// <see cref="PqKdf.Argon2id"/> for memory-hard resistance to GPU/ASIC cracking.
    /// Ignored for recipient (public-key) encryption.
    /// </summary>
    public PqKdf Kdf { get; init; } = PqKdf.Pbkdf2HmacSha256;

    /// <summary>
    /// PBKDF2-HMAC-SHA256 iteration count. Default is 600,000, matching the OWASP
    /// recommendation. Used only when <see cref="Kdf"/> is <see cref="PqKdf.Pbkdf2HmacSha256"/>.
    /// </summary>
    public int Pbkdf2Iterations { get; init; } = 600_000;

    /// <summary>
    /// Argon2id memory cost in kibibytes. Default is 19,456 KiB (19 MiB), an OWASP-recommended
    /// setting. Used only when <see cref="Kdf"/> is <see cref="PqKdf.Argon2id"/>.
    /// </summary>
    public int Argon2MemoryKiB { get; init; } = 19_456;

    /// <summary>Argon2id iteration (pass) count. Default is 2. Used only with Argon2id.</summary>
    public int Argon2Iterations { get; init; } = 2;

    /// <summary>Argon2id degree of parallelism. Default is 1. Used only with Argon2id.</summary>
    public int Argon2Parallelism { get; init; } = 1;

    /// <summary>
    /// Length, in bytes, of the random per-file KDF salt. Default is 16 (128 bits).
    /// </summary>
    public int SaltSizeBytes { get; init; } = 16;

    /// <summary>
    /// Plaintext size, in bytes, of each authenticated chunk. Default is 64 KiB.
    /// Smaller chunks lower peak memory; larger chunks reduce per-chunk overhead.
    /// </summary>
    public int ChunkSizeBytes { get; init; } = 64 * 1024;

    /// <summary>A shared instance carrying the default options (PBKDF2-HMAC-SHA256, 600,000 iterations).</summary>
    public static PqEncryptionOptions Default { get; } = new();

    /// <summary>
    /// A shared preset carrying the Argon2id defaults (19 MiB memory, 2 iterations, parallelism 1) —
    /// a one-liner alternative to <c>new PqEncryptionOptions { Kdf = PqKdf.Argon2id }</c>.
    /// </summary>
    public static PqEncryptionOptions Argon2id { get; } = new() { Kdf = PqKdf.Argon2id };

    /// <summary>
    /// Returns a copy of these options that uses Argon2id, optionally overriding any of the
    /// Argon2id tuning parameters. Unspecified parameters keep their current value, so this
    /// composes cleanly with <see cref="Default"/> or with an existing options instance.
    /// </summary>
    /// <example>
    /// <code>
    /// // Stronger Argon2id (64 MiB) for sensitive archives:
    /// var opts = PqEncryptionOptions.Default.WithArgon2id(memoryKiB: 64 * 1024);
    /// </code>
    /// </example>
    public PqEncryptionOptions WithArgon2id(
        int? memoryKiB = null, int? iterations = null, int? parallelism = null) => new()
        {
            Kdf = PqKdf.Argon2id,
            Argon2MemoryKiB = memoryKiB ?? Argon2MemoryKiB,
            Argon2Iterations = iterations ?? Argon2Iterations,
            Argon2Parallelism = parallelism ?? Argon2Parallelism,
            Pbkdf2Iterations = Pbkdf2Iterations,
            SaltSizeBytes = SaltSizeBytes,
            ChunkSizeBytes = ChunkSizeBytes,
        };

    /// <summary>
    /// Returns a copy of these options that uses PBKDF2-HMAC-SHA256, optionally overriding the
    /// iteration count. Convenient when you want to keep some shared base options but bump
    /// (or relax) the work factor.
    /// </summary>
    public PqEncryptionOptions WithPbkdf2(int? iterations = null) => new()
        {
            Kdf = PqKdf.Pbkdf2HmacSha256,
            Pbkdf2Iterations = iterations ?? Pbkdf2Iterations,
            Argon2MemoryKiB = Argon2MemoryKiB,
            Argon2Iterations = Argon2Iterations,
            Argon2Parallelism = Argon2Parallelism,
            SaltSizeBytes = SaltSizeBytes,
            ChunkSizeBytes = ChunkSizeBytes,
        };

    /// <summary>
    /// Returns a copy of these options with a different chunk size. Useful for tuning peak
    /// memory or throughput without changing key derivation.
    /// </summary>
    /// <param name="chunkSizeBytes">Plaintext bytes per authenticated chunk. The supported range
    /// is between <c>1 KiB</c> and <c>16 MiB</c>; out-of-range values throw at encrypt time.</param>
    public PqEncryptionOptions WithChunkSize(int chunkSizeBytes) => new()
        {
            Kdf = Kdf,
            Pbkdf2Iterations = Pbkdf2Iterations,
            Argon2MemoryKiB = Argon2MemoryKiB,
            Argon2Iterations = Argon2Iterations,
            Argon2Parallelism = Argon2Parallelism,
            SaltSizeBytes = SaltSizeBytes,
            ChunkSizeBytes = chunkSizeBytes,
        };

    // Lower bounds keep the format honest; upper bounds cap the work a (possibly hostile)
    // container header can demand, so a malicious file fails closed instead of exhausting
    // memory or CPU. An attacker-supplied header that violates these is rejected at
    // decryption time as a PqFormatException, not here.
    internal const int MinPbkdf2Iterations = 100_000;
    internal const int MaxPbkdf2Iterations = 100_000_000;
    internal const int MinArgon2MemoryKiB = 8 * 1024;     // 8 MiB
    internal const int MaxArgon2MemoryKiB = 2 * 1024 * 1024; // 2 GiB
    internal const int MinArgon2Iterations = 1;
    internal const int MaxArgon2Iterations = 10_000;
    internal const int MinSaltSizeBytes = 8;
    internal const int MinChunkSizeBytes = 1024;            // 1 KiB
    internal const int MaxChunkSizeBytes = 16 * 1024 * 1024; // 16 MiB — bounds peak memory

    /// <summary>
    /// Throws <see cref="ArgumentOutOfRangeException"/> if any option is outside its supported
    /// range. Called by the encryptor before any work begins (fail fast).
    /// </summary>
    internal void Validate()
    {
        if (SaltSizeBytes < MinSaltSizeBytes || SaltSizeBytes > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(SaltSizeBytes), SaltSizeBytes,
                $"Salt size must be between {MinSaltSizeBytes} and {byte.MaxValue} bytes.");
        }

        if (ChunkSizeBytes < MinChunkSizeBytes || ChunkSizeBytes > MaxChunkSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ChunkSizeBytes), ChunkSizeBytes,
                $"Chunk size must be between {MinChunkSizeBytes} and {MaxChunkSizeBytes} bytes.");
        }

        switch (Kdf)
        {
            case PqKdf.Pbkdf2HmacSha256:
                if (Pbkdf2Iterations < MinPbkdf2Iterations || Pbkdf2Iterations > MaxPbkdf2Iterations)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(Pbkdf2Iterations), Pbkdf2Iterations,
                        $"PBKDF2 iteration count must be between {MinPbkdf2Iterations} and {MaxPbkdf2Iterations}.");
                }
                break;

            case PqKdf.Argon2id:
                if (Argon2MemoryKiB < MinArgon2MemoryKiB || Argon2MemoryKiB > MaxArgon2MemoryKiB)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(Argon2MemoryKiB), Argon2MemoryKiB,
                        $"Argon2id memory must be between {MinArgon2MemoryKiB} and {MaxArgon2MemoryKiB} KiB.");
                }
                if (Argon2Iterations < MinArgon2Iterations || Argon2Iterations > MaxArgon2Iterations)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(Argon2Iterations), Argon2Iterations,
                        $"Argon2id iterations must be between {MinArgon2Iterations} and {MaxArgon2Iterations}.");
                }
                if (Argon2Parallelism < 1 || Argon2Parallelism > byte.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(Argon2Parallelism), Argon2Parallelism,
                        $"Argon2id parallelism must be between 1 and {byte.MaxValue}.");
                }
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(Kdf), Kdf, "Unknown KDF.");
        }
    }
}
