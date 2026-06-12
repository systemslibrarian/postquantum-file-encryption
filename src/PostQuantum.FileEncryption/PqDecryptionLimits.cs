namespace PostQuantum.FileEncryption;

/// <summary>
/// Ceilings on the work a container header may demand of <see cref="PqFileDecryptor"/>.
/// A container's KDF cost parameters and chunk size are read from its (attacker-controllable)
/// header <em>before</em> anything has been authenticated, so a hostile file could otherwise
/// legally demand the format's maximum — up to 2 GiB of Argon2id memory or a 16 MiB chunk
/// buffer — from a few dozen bytes of input. These limits let a caller who decrypts
/// <em>untrusted</em> containers cap that cost; a header exceeding a limit is rejected with
/// <see cref="PqFormatException"/> before any key derivation or buffer allocation happens.
/// </summary>
/// <remarks>
/// The defaults equal the format's own maxima, so <c>new PqFileDecryptor()</c> behaves exactly
/// as before and every legal container decrypts. Use <see cref="Untrusted"/> (or your own
/// values) when the containers you open come from sources you do not control. Lowering a limit
/// never weakens cryptographic security — it only narrows which (legitimately expensive)
/// containers you are willing to pay to open.
/// </remarks>
public sealed class PqDecryptionLimits
{
    /// <summary>
    /// Highest PBKDF2-HMAC-SHA256 iteration count this decryptor will honor.
    /// Defaults to the format maximum (100,000,000).
    /// </summary>
    public int MaxPbkdf2Iterations { get; init; } = PqEncryptionOptions.MaxPbkdf2Iterations;

    /// <summary>
    /// Highest Argon2id memory cost, in kibibytes, this decryptor will honor.
    /// Defaults to the format maximum (2,097,152 KiB = 2 GiB).
    /// </summary>
    public int MaxArgon2MemoryKiB { get; init; } = PqEncryptionOptions.MaxArgon2MemoryKiB;

    /// <summary>
    /// Highest Argon2id iteration (pass) count this decryptor will honor.
    /// Defaults to the format maximum (10,000).
    /// </summary>
    public int MaxArgon2Iterations { get; init; } = PqEncryptionOptions.MaxArgon2Iterations;

    /// <summary>
    /// Largest chunk size, in bytes, this decryptor will allocate buffers for.
    /// Defaults to the format maximum (16 MiB).
    /// </summary>
    public int MaxChunkSizeBytes { get; init; } = PqEncryptionOptions.MaxChunkSizeBytes;

    /// <summary>The permissive defaults: every limit equals the format maximum, so every legal container decrypts.</summary>
    public static PqDecryptionLimits Default { get; } = new();

    /// <summary>
    /// A conservative preset for containers from untrusted sources: PBKDF2 ≤ 2,000,000
    /// iterations, Argon2id ≤ 256 MiB memory and ≤ 10 passes, chunk size ≤ 4 MiB. Every
    /// container produced with this library's defaults (and any reasonable tuning) stays well
    /// inside these ceilings; what gets rejected is the pathological header crafted to make
    /// you burn gibibytes of memory or minutes of CPU before the first authentication check.
    /// </summary>
    public static PqDecryptionLimits Untrusted { get; } = new()
    {
        MaxPbkdf2Iterations = 2_000_000,
        MaxArgon2MemoryKiB = 256 * 1024,
        MaxArgon2Iterations = 10,
        MaxChunkSizeBytes = 4 * 1024 * 1024,
    };

    /// <summary>
    /// Throws <see cref="ArgumentOutOfRangeException"/> if any limit falls outside the format's
    /// own [minimum, maximum] range — a limit below the format minimum would reject every
    /// container and is certainly a configuration mistake.
    /// </summary>
    internal void Validate()
    {
        if (MaxPbkdf2Iterations < PqEncryptionOptions.MinPbkdf2Iterations
            || MaxPbkdf2Iterations > PqEncryptionOptions.MaxPbkdf2Iterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxPbkdf2Iterations), MaxPbkdf2Iterations,
                $"Limit must be between {PqEncryptionOptions.MinPbkdf2Iterations} and {PqEncryptionOptions.MaxPbkdf2Iterations}.");
        }

        if (MaxArgon2MemoryKiB < PqEncryptionOptions.MinArgon2MemoryKiB
            || MaxArgon2MemoryKiB > PqEncryptionOptions.MaxArgon2MemoryKiB)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxArgon2MemoryKiB), MaxArgon2MemoryKiB,
                $"Limit must be between {PqEncryptionOptions.MinArgon2MemoryKiB} and {PqEncryptionOptions.MaxArgon2MemoryKiB} KiB.");
        }

        if (MaxArgon2Iterations < PqEncryptionOptions.MinArgon2Iterations
            || MaxArgon2Iterations > PqEncryptionOptions.MaxArgon2Iterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxArgon2Iterations), MaxArgon2Iterations,
                $"Limit must be between {PqEncryptionOptions.MinArgon2Iterations} and {PqEncryptionOptions.MaxArgon2Iterations}.");
        }

        if (MaxChunkSizeBytes < PqEncryptionOptions.MinChunkSizeBytes
            || MaxChunkSizeBytes > PqEncryptionOptions.MaxChunkSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxChunkSizeBytes), MaxChunkSizeBytes,
                $"Limit must be between {PqEncryptionOptions.MinChunkSizeBytes} and {PqEncryptionOptions.MaxChunkSizeBytes} bytes.");
        }
    }
}
