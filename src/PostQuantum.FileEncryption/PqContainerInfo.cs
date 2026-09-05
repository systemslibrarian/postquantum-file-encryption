using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption;

/// <summary>The key-establishment mode a <c>.pqfe</c> container header declares.</summary>
public enum PqKeySource
{
    /// <summary>Passphrase-derived content key (PBKDF2-HMAC-SHA256 or Argon2id).</summary>
    Passphrase = 1,

    /// <summary>Inline ML-KEM-768 recipient (deprecated mode; prefer the Hybrid package).</summary>
    MlKemRecipient = 2,

    /// <summary>X25519 + ML-KEM-768 hybrid recipient (the Hybrid package).</summary>
    HybridRecipient = 3,

    /// <summary>Multiple X25519 + ML-KEM-768 hybrid recipients (the Hybrid package).</summary>
    HybridMultiRecipient = 4,

    /// <summary>External envelope key provider — KMS, HSM, or local KEK.</summary>
    KeyProvider = 5,
}

/// <summary>
/// Structural facts read from a <c>.pqfe</c> container's header — the supported way to answer
/// "what would decrypting this cost, and which key do I need?" without hand-parsing the frozen
/// format: the key source, the KDF and its declared work factors, the chunk size, the provider
/// id, and (when the container's length is known) an exact upper bound on the plaintext size.
/// Reading is cheap and performs <b>no</b> key derivation or decryption, so it is safe to run
/// on untrusted input before deciding whether to decrypt at all — the natural place to enforce
/// an application's own policy ("hybrid recipients only", "no KDF below our floor", "nothing
/// over 100 MB") on top of <see cref="PqDecryptionLimits"/>.
/// </summary>
/// <remarks>
/// <b>Everything here is unauthenticated.</b> The header is attacker-controllable until a
/// decryption completes (it is bound as AAD, so it cannot be <i>altered</i> for an existing
/// container — but a hostile file can claim anything). Use these values to refuse work or
/// pick a key, never as a trusted statement about the plaintext. Structurally invalid input
/// throws <see cref="PqFormatException"/>, mirroring the real reader's acceptance exactly.
/// </remarks>
public sealed class PqContainerInfo
{
    private PqContainerInfo(ContainerHeader header, long? totalContainerBytes)
    {
        FormatVersion = ContainerFormat.FormatVersion;
        KeySource = (PqKeySource)header.KeySource;
        ChunkSizeBytes = header.ChunkSize;
        PlaintextSizeUpperBoundBytes = PqContainerEngine.DerivePlaintextTotal(totalContainerBytes, header);

        ReadOnlySpan<byte> p = header.KeyParams;
        switch (header.KeySource)
        {
            case ContainerFormat.KeySourcePassphrase:
                ParsePassphraseParams(p);
                break;
            case ContainerFormat.KeySourceMlKemRecipient:
                // Exact layout enforced by the real reader: KemId(1) | C(2) | KemCt(C) |
                // WrapNonce(12) | WrapTag(16) | WrappedKey(32), with KemId 1 ⇒ C = 1088.
                if (p.Length < 3 || p[0] != 1
                    || BinaryPrimitives.ReadUInt16BigEndian(p[1..]) != 1088
                    || p.Length != 3 + 1088 + 12 + 16 + 32)
                {
                    throw new PqFormatException("The recipient key parameters are malformed.");
                }
                RecipientCount = 1;
                break;
            case ContainerFormat.KeySourceHybridRecipient:
                // A single hybrid wrap block: KemId(1) | C(2) | KemCt(1088) | EphX25519(32) |
                // WrapNonce(12) | WrapTag(16) | WrappedKey(32) — exact length 1183.
                if (p.Length != 1183)
                {
                    throw new PqFormatException("The hybrid recipient key parameters are malformed.");
                }
                RecipientCount = 1;
                break;
            case ContainerFormat.KeySourceMultiRecipient:
                RecipientCount = ParseMultiRecipientCount(p);
                break;
            case ContainerFormat.KeySourceKeyProvider:
                KeyProviderId = ParseProviderId(p);
                break;
            default:
                // Unreachable: ContainerHeader.Parse already rejected unknown key sources.
                throw new PqFormatException("Unsupported key source.");
        }
    }

    /// <summary>The container format version (always <c>2</c> for the frozen 1.x format).</summary>
    public int FormatVersion { get; }

    /// <summary>The declared key-establishment mode — which kind of key opens this container.</summary>
    public PqKeySource KeySource { get; }

    /// <summary>The declared chunk size in bytes (bounds the decryptor's buffer per chunk).</summary>
    public int ChunkSizeBytes { get; }

    /// <summary>The declared KDF, for <see cref="PqKeySource.Passphrase"/> containers.</summary>
    public PqKdf? Kdf { get; private set; }

    /// <summary>The declared salt length in bytes, for passphrase containers.</summary>
    public int? SaltSizeBytes { get; private set; }

    /// <summary>The declared PBKDF2 iteration count — the CPU cost decryption would pay.</summary>
    public int? Pbkdf2Iterations { get; private set; }

    /// <summary>The declared Argon2id memory cost in KiB — the memory decryption would commit.</summary>
    public int? Argon2MemoryKiB { get; private set; }

    /// <summary>The declared Argon2id pass count.</summary>
    public int? Argon2Iterations { get; private set; }

    /// <summary>The declared Argon2id lane count.</summary>
    public int? Argon2Parallelism { get; private set; }

    /// <summary>
    /// The number of recipient wrap blocks the header declares (1 for the single-recipient
    /// modes). Blocks past the declared count — a frozen reader leniency — are not counted.
    /// </summary>
    public int? RecipientCount { get; private set; }

    /// <summary>
    /// The declared key-provider id, for <see cref="PqKeySource.KeyProvider"/> containers,
    /// with control characters replaced by <c>?</c> (the raw value is attacker-controlled
    /// text and must not reach a log or terminal unsanitized).
    /// </summary>
    public string? KeyProviderId { get; private set; }

    /// <summary>
    /// An exact upper bound on the plaintext this container can decrypt to, derived from the
    /// container's total length — or <see langword="null"/> when the length was unknown or
    /// too short to hold any frame. This is the same bound
    /// <see cref="PqDecryptionLimits.MaxPlaintextBytes"/> enforces.
    /// </summary>
    public long? PlaintextSizeUpperBoundBytes { get; }

    /// <summary>
    /// Reads the structural facts from a complete (or prefix of a) container. Throws
    /// <see cref="PqFormatException"/> for input the frozen reader would reject structurally.
    /// </summary>
    public static PqContainerInfo Read(ReadOnlySpan<byte> container)
    {
        if (container.Length < ContainerFormat.FixedHeaderLength)
        {
            throw new PqFormatException("Input is too short to be a PostQuantum.FileEncryption container.");
        }
        int keyParamsLength = BinaryPrimitives.ReadUInt16BigEndian(container[ContainerFormat.OffsetKeyParamsLength..]);
        int headerLength = ContainerFormat.FixedHeaderLength + keyParamsLength;
        if (container.Length < headerLength)
        {
            throw new PqFormatException("Input ends before the declared container header is complete.");
        }
        ContainerHeader header = ContainerHeader.Parse(container[..headerLength].ToArray());
        return new PqContainerInfo(header, container.Length);
    }

    /// <summary>
    /// Like <see cref="Read(ReadOnlySpan{byte})"/>, but returns <see langword="false"/>
    /// instead of throwing for structurally invalid input.
    /// </summary>
    public static bool TryRead(ReadOnlySpan<byte> container, [NotNullWhen(true)] out PqContainerInfo? info)
    {
        try
        {
            info = Read(container);
            return true;
        }
        catch (PqFormatException)
        {
            info = null;
            return false;
        }
    }

    /// <summary>Reads the structural facts from a container file (header bytes only are read).</summary>
    public static async Task<PqContainerInfo> ReadFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        await using var stream = FileIo.OpenRead(path);
        long total = stream.Length;
        ContainerHeader header = await PqContainerEngine.ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(false);
        return new PqContainerInfo(header, total);
    }

    private void ParsePassphraseParams(ReadOnlySpan<byte> p)
    {
        // The same structural checks (and bounds) as the real reader's key establishment —
        // pinned against it by the conformance-corpus consistency tests.
        if (p.Length < 2)
        {
            throw new PqFormatException("Passphrase key parameters are too short.");
        }
        byte kdfId = p[0];
        int saltLength = p[1];
        int offset = 2;
        if (saltLength < PqEncryptionOptions.MinSaltSizeBytes || p.Length < offset + saltLength)
        {
            throw new PqFormatException("Container declares an invalid salt.");
        }
        SaltSizeBytes = saltLength;
        offset += saltLength;

        switch (kdfId)
        {
            case ContainerFormat.KdfPbkdf2HmacSha256:
            {
                if (p.Length < offset + 4)
                {
                    throw new PqFormatException("PBKDF2 key parameters are truncated.");
                }
                long iterations = BinaryPrimitives.ReadUInt32BigEndian(p[offset..]);
                if (iterations < PqEncryptionOptions.MinPbkdf2Iterations || iterations > PqEncryptionOptions.MaxPbkdf2Iterations)
                {
                    throw new PqFormatException($"Container declares an out-of-range PBKDF2 iteration count of {iterations}.");
                }
                Kdf = PqKdf.Pbkdf2HmacSha256;
                Pbkdf2Iterations = (int)iterations;
                break;
            }
            case ContainerFormat.KdfArgon2id:
            {
                if (p.Length < offset + 9)
                {
                    throw new PqFormatException("Argon2id key parameters are truncated.");
                }
                long memoryKiB = BinaryPrimitives.ReadUInt32BigEndian(p[offset..]);
                long iterations = BinaryPrimitives.ReadUInt32BigEndian(p[(offset + 4)..]);
                int parallelism = p[offset + 8];
                if (memoryKiB < PqEncryptionOptions.MinArgon2MemoryKiB || memoryKiB > PqEncryptionOptions.MaxArgon2MemoryKiB ||
                    iterations < PqEncryptionOptions.MinArgon2Iterations || iterations > PqEncryptionOptions.MaxArgon2Iterations ||
                    parallelism < 1)
                {
                    throw new PqFormatException("Container declares out-of-range Argon2id parameters.");
                }
                Kdf = PqKdf.Argon2id;
                Argon2MemoryKiB = (int)memoryKiB;
                Argon2Iterations = (int)iterations;
                Argon2Parallelism = parallelism;
                break;
            }
            default:
                throw new PqFormatException($"Unsupported KDF identifier {kdfId}.");
        }
    }

    private static int ParseMultiRecipientCount(ReadOnlySpan<byte> p)
    {
        // Count byte followed by `count` entries of Mode(1) | BlockLength(2 BE) | Block.
        // Trailing bytes past the declared count are a frozen reader leniency and are ignored,
        // exactly as the real reader ignores them.
        if (p.Length < 1 || p[0] < 1)
        {
            throw new PqFormatException("The multi-recipient key parameters are malformed.");
        }
        int count = p[0];
        int cursor = 1;
        for (int i = 0; i < count; i++)
        {
            if (p.Length < cursor + 3)
            {
                throw new PqFormatException("The multi-recipient key parameters are malformed.");
            }
            int blockLength = BinaryPrimitives.ReadUInt16BigEndian(p[(cursor + 1)..]);
            cursor += 3;
            if (p.Length < cursor + blockLength)
            {
                throw new PqFormatException("The multi-recipient key parameters are malformed.");
            }
            cursor += blockLength;
        }
        return count;
    }

    private static string ParseProviderId(ReadOnlySpan<byte> p)
    {
        // ProviderIdLength(1) | ProviderId(UTF-8) | WrapInfoLength(2 BE) | WrapInfo — exact.
        if (p.Length < 1)
        {
            throw new PqFormatException("The key-provider parameters are malformed.");
        }
        int idLength = p[0];
        if (idLength < 1 || p.Length < 1 + idLength + 2)
        {
            throw new PqFormatException("The key-provider parameters are malformed.");
        }
        int wrapInfoLength = BinaryPrimitives.ReadUInt16BigEndian(p[(1 + idLength)..]);
        if (p.Length != 1 + idLength + 2 + wrapInfoLength)
        {
            throw new PqFormatException("The key-provider parameters are malformed.");
        }
        return PqContainer.SanitizeForMessage(System.Text.Encoding.UTF8.GetString(p.Slice(1, idLength)));
    }
}
