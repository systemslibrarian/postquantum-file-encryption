using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Hybrid.Internal;
using PostQuantum.FileEncryption.Internal;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

// ---------------------------------------------------------------- manifest model

/// <summary>The machine-readable conformance manifest (<c>test-vectors/manifest.json</c>).</summary>
internal sealed record ConformanceManifest(
    int FormatVersion,
    string Description,
    IReadOnlyList<ConformanceVector> Vectors);

/// <summary>One conformance case: a committed vector plus the outcome a conforming reader must produce.</summary>
internal sealed record ConformanceVector
{
    /// <summary>Stable identifier for the case.</summary>
    public required string Id { get; init; }

    /// <summary><c>positive</c> | <c>negative</c> | <c>lenient</c>.</summary>
    public required string Category { get; init; }

    /// <summary><c>accept</c> | <c>reject-format</c> | <c>reject-decryption</c>.</summary>
    public required string Expect { get; init; }

    /// <summary>The vector file, relative to <c>test-vectors/</c>.</summary>
    public required string File { get; init; }

    /// <summary>Lowercase hex SHA-256 of <see cref="File"/> — the frozen-artifact pin.</summary>
    public required string Sha256 { get; init; }

    /// <summary>The <c>KeySource</c> the case exercises, where applicable.</summary>
    public int? KeySource { get; init; }

    /// <summary>Passphrase to decrypt with (accepts) or attempt with (rejects), for passphrase cases.</summary>
    public string? Passphrase { get; init; }

    /// <summary>Expected UTF-8 plaintext for an <c>accept</c> case.</summary>
    public string? PlaintextUtf8 { get; init; }

    /// <summary>Recipient private-key file (relative to <c>test-vectors/</c>) for a hybrid <c>accept</c> case.</summary>
    public string? PrivateKeyFile { get; init; }

    /// <summary>For a negative/lenient case: the frozen positive it was mechanically derived from.</summary>
    public string? DerivedFrom { get; init; }

    /// <summary>Human description of the mutation or construction.</summary>
    public string? Notes { get; init; }
}

// ---------------------------------------------------------------- generator

/// <summary>
/// Regenerates the committed conformance-vector corpus (<c>test-vectors/manifest.json</c> plus the
/// <c>negative/</c> and <c>lenient/</c> artifacts) that <see cref="ConformanceManifestTests"/> and the
/// Rust core's <c>tests/conformance.rs</c> both check. It is a tool, not a CI test: it runs only when
/// <c>PQFE_REGEN_VECTORS=1</c>, so a normal test run never rewrites the frozen bytes.
/// </summary>
/// <remarks>
/// The negatives are deterministic single-mutation derivatives of the frozen
/// <c>passphrase-pbkdf2.pqfe</c> vector; the passphrase lenient vectors are built deterministically
/// from fixed key material. The one hybrid lenient vector uses randomized KEM encapsulation, so it is
/// generated once and pinned — like Vectors 6/8 in <c>docs/TEST-VECTORS.md</c>.
/// </remarks>
public sealed class ConformanceVectorGenerator
{
    private static readonly byte[] Passphrase = "test-vector-passphrase"u8.ToArray();

    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    [Fact]
    public async Task Regenerate_conformance_corpus()
    {
        if (Environment.GetEnvironmentVariable("PQFE_REGEN_VECTORS") != "1")
        {
            return; // tool mode only; a normal run must never rewrite the frozen corpus
        }

        string root = ConformanceManifestTests.FindRepositoryRoot();
        string dir = Path.Combine(root, "test-vectors");
        Directory.CreateDirectory(Path.Combine(dir, "negative"));
        Directory.CreateDirectory(Path.Combine(dir, "lenient"));

        var vectors = new List<ConformanceVector>();

        // ---- positives already committed (verified here via the manifest too) ----
        vectors.Add(Positive("pos-passphrase-pbkdf2", "passphrase-pbkdf2.pqfe", 1, dir,
            "test-vector-passphrase", "PostQuantum.FileEncryption known-answer vector v2.",
            "Frozen KAT Vector 1 (PBKDF2-HMAC-SHA256)."));
        vectors.Add(Positive("pos-passphrase-argon2id", "passphrase-argon2id.pqfe", 1, dir,
            "test-vector-passphrase", "PostQuantum.FileEncryption known-answer vector v2.",
            "Frozen KAT Vector 2 (Argon2id)."));
        vectors.Add(Positive("pos-passphrase-pbkdf2-rustcore", "passphrase-pbkdf2-rustcore.pqfe", 1, dir,
            "cross-impl-passphrase", "Encrypted by the Rust/WASM core, decrypted by .NET.",
            "Frozen KAT Vector 3 (produced by the Rust core)."));

        // A deterministic TWO-chunk container (1024-byte chunks): the base for the
        // frame-ordering and cross-container negatives below, and a positive pin for
        // multi-frame decryption in both implementations.
        string multiChunkPlaintext = string.Concat(Enumerable.Repeat("PQFE multi-chunk conformance vector. ", 56))[..2048];
        byte[] multiChunk = await MakePassphraseContainerAsync(
            salt: Filled(0x40, 16), iterations: 100_000, noncePrefix: Filled(0x44, 4),
            plaintext: Encoding.UTF8.GetBytes(multiChunkPlaintext), flags: 0x00, keyParamsTrailing: null);
        vectors.Add(new ConformanceVector
        {
            Id = "pos-passphrase-pbkdf2-multichunk",
            Category = "positive",
            Expect = "accept",
            File = "passphrase-pbkdf2-multichunk.pqfe",
            Sha256 = Write(dir, "passphrase-pbkdf2-multichunk.pqfe", multiChunk),
            KeySource = 1,
            Passphrase = "test-vector-passphrase",
            PlaintextUtf8 = multiChunkPlaintext,
            Notes = "Deterministic two-chunk container (1024-byte chunks, PBKDF2 100k): pins "
                + "frame ordering, the final-frame marker, and multi-frame decryption cross-implementation.",
        });

        // ---- negatives: deterministic single mutations of the frozen PBKDF2 vector ----
        byte[] baseVector = await File.ReadAllBytesAsync(Path.Combine(dir, "passphrase-pbkdf2.pqfe"));
        int headerLen = ContainerFormat.FixedHeaderLength
            + BinaryPrimitives.ReadUInt16BigEndian(baseVector.AsSpan(ContainerFormat.OffsetKeyParamsLength));
        int saltLen = baseVector[ContainerFormat.FixedHeaderLength + 1];
        int iterOffset = ContainerFormat.FixedHeaderLength + 2 + saltLen;

        vectors.Add(Negative("neg-bad-magic", "reject-format", Mutate(baseVector, m => m[0] ^= 0xFF), dir,
            "First magic byte flipped: not a PQFE container."));
        vectors.Add(Negative("neg-bad-version", "reject-format", Mutate(baseVector, m => m[ContainerFormat.OffsetFormatVersion] = 3), dir,
            "FormatVersion set to 3: unsupported version."));
        vectors.Add(Negative("neg-unknown-aead", "reject-format", Mutate(baseVector, m => m[ContainerFormat.OffsetAeadId] = 2), dir,
            "AeadId set to 2: only 1 (AES-256-GCM) is defined at v2."));
        vectors.Add(Negative("neg-unknown-keysource", "reject-format", Mutate(baseVector, m => m[ContainerFormat.OffsetKeySource] = 9), dir,
            "KeySource set to 9: not a defined key source."));
        vectors.Add(Negative("neg-chunksize-zero", "reject-format",
            Mutate(baseVector, m => BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(ContainerFormat.OffsetChunkSize), 0)), dir,
            "ChunkSize set to 0: below the 1024-byte floor, rejected before any KDF work."));
        vectors.Add(Negative("neg-pbkdf2-iterations-out-of-range", "reject-format",
            Mutate(baseVector, m => BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(iterOffset), 1)), dir,
            "PBKDF2 iteration count set to 1: range-checked and rejected before deriving the key."));
        vectors.Add(Negative("neg-header-tamper", "reject-decryption", Mutate(baseVector, m => m[ContainerFormat.OffsetNoncePrefix] ^= 0x01), dir,
            "One nonce-prefix byte flipped: the header is per-frame AAD, so every frame fails authentication."));
        vectors.Add(Negative("neg-ciphertext-tamper", "reject-decryption", Mutate(baseVector, m => m[headerLen + 1] ^= 0x01), dir,
            "One frame byte flipped: authentication fails."));
        vectors.Add(Negative("neg-tag-truncated", "reject-decryption", baseVector[..^ContainerFormat.TagLength], dir,
            "Final 16-byte tag dropped: truncation fails closed."));
        vectors.Add(Negative("neg-prefix-truncated", "reject-decryption", baseVector[..(headerLen + 8)], dir,
            "Truncated mid-frame after the header: no authenticated final frame."));
        vectors.Add(Negative("neg-not-a-container", "reject-format", new byte[64], dir,
            "64 zero bytes: no PQFE magic."));

        // ---- negatives derived from the frozen Argon2id vector: cost/salt bounds ----
        // These pin the CONFORMANCE.md 2.1 rule-5 MUSTs for the Argon2id side — the checks
        // that stop a ~90-byte hostile header demanding 2 GiB of memory — in BOTH readers.
        byte[] argonBase = await File.ReadAllBytesAsync(Path.Combine(dir, "passphrase-argon2id.pqfe"));
        int argonSaltLen = argonBase[ContainerFormat.FixedHeaderLength + 1];
        int argonParams = ContainerFormat.FixedHeaderLength + 2 + argonSaltLen; // MemoryKiB(4) ‖ Iterations(4) ‖ Parallelism(1)

        vectors.Add(Negative("neg-argon2-memory-out-of-range", "reject-format",
            Mutate(argonBase, m => BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(argonParams), 2_097_153)), dir,
            "Argon2id memory set to 2,097,153 KiB — one above the format maximum; rejected before any derivation.",
            derivedFrom: "passphrase-argon2id.pqfe"));
        vectors.Add(Negative("neg-argon2-iterations-out-of-range", "reject-format",
            Mutate(argonBase, m => BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(argonParams + 4), 10_001)), dir,
            "Argon2id iterations set to 10,001 — one above the format maximum; rejected before any derivation.",
            derivedFrom: "passphrase-argon2id.pqfe"));
        vectors.Add(Negative("neg-argon2-parallelism-zero", "reject-format",
            Mutate(argonBase, m => m[argonParams + 8] = 0), dir,
            "Argon2id parallelism set to 0 — below the minimum of 1; rejected before any derivation.",
            derivedFrom: "passphrase-argon2id.pqfe"));
        vectors.Add(Negative("neg-salt-too-short", "reject-format",
            Mutate(argonBase, m => m[ContainerFormat.FixedHeaderLength + 1] = 7), dir,
            "Declared salt length set to 7 — below the 8-byte floor; rejected before any derivation.",
            derivedFrom: "passphrase-argon2id.pqfe"));

        // ---- clean-boundary truncation: header only, zero frames ----
        vectors.Add(Negative("neg-truncated-at-frame-boundary", "reject-decryption",
            baseVector[..headerLen], dir,
            "Container cut exactly at the header/frame boundary: parses cleanly but carries no "
            + "authenticated final frame, so a conforming reader must reject it."));

        // ---- frame-ordering and cross-container negatives from the multi-chunk vector ----
        int mcHeaderLen = ContainerFormat.FixedHeaderLength
            + BinaryPrimitives.ReadUInt16BigEndian(multiChunk.AsSpan(ContainerFormat.OffsetKeyParamsLength));
        int mcFrame = 5 + 1024 + ContainerFormat.TagLength;

        byte[] frameSwap = (byte[])multiChunk.Clone();
        Array.Copy(multiChunk, mcHeaderLen + mcFrame, frameSwap, mcHeaderLen, mcFrame);
        Array.Copy(multiChunk, mcHeaderLen, frameSwap, mcHeaderLen + mcFrame, mcFrame);
        vectors.Add(Negative("neg-frame-swap", "reject-decryption", frameSwap, dir,
            "The two frames of the multi-chunk vector swapped on disk: each frame's ordinal is "
            + "bound as AAD, so reordering fails authentication.",
            derivedFrom: "passphrase-pbkdf2-multichunk.pqfe"));

        vectors.Add(Negative("neg-final-frame-dropped", "reject-decryption",
            multiChunk[..(mcHeaderLen + mcFrame)], dir,
            "The multi-chunk vector cut cleanly after its first (authentic, non-final) frame: "
            + "no authenticated final marker, so a conforming reader must reject it.",
            derivedFrom: "passphrase-pbkdf2-multichunk.pqfe"));

        byte[] otherContainer = await MakePassphraseContainerAsync(
            salt: Filled(0x50, 16), iterations: 100_000, noncePrefix: Filled(0x55, 4),
            plaintext: Encoding.UTF8.GetBytes(multiChunkPlaintext), flags: 0x00, keyParamsTrailing: null);
        if (otherContainer.Length != multiChunk.Length)
        {
            throw new InvalidOperationException("Cross-container bases must be structurally identical.");
        }
        byte[] transplant = (byte[])multiChunk.Clone();
        Array.Copy(otherContainer, mcHeaderLen, transplant, mcHeaderLen, mcFrame);
        vectors.Add(Negative("neg-cross-container-transplant", "reject-decryption", transplant, dir,
            "Frame 0 of a second container (same passphrase, same plaintext, different salt and "
            + "nonce prefix) transplanted into the multi-chunk vector at the same ordinal: the "
            + "per-encryption key and header-as-AAD separation must reject splicing between containers.",
            derivedFrom: "passphrase-pbkdf2-multichunk.pqfe"));

        // A negative that needs no new file: the frozen vector with the wrong passphrase.
        var good = vectors[0];
        vectors.Add(new ConformanceVector
        {
            Id = "neg-wrong-passphrase",
            Category = "negative",
            Expect = "reject-decryption",
            File = good.File,
            Sha256 = good.Sha256,
            KeySource = 1,
            Passphrase = "wrong-passphrase",
            DerivedFrom = good.File,
            Notes = "The frozen Vector 1 opened with the wrong passphrase: fails closed, no oracle.",
        });

        // ---- lenient corners: frozen v2 reader accepts these (CONFORMANCE.md 2.2) ----
        byte[] flagsContainer = await MakePassphraseContainerAsync(
            salt: Filled(0x10, 16), iterations: 100_000, noncePrefix: Filled(0x11, 4),
            plaintext: "PostQuantum.FileEncryption conformance: reserved Flags byte set to 0x01."u8.ToArray(),
            flags: 0x01, keyParamsTrailing: null);
        vectors.Add(Lenient("lenient-nonzero-flags", "lenient/nonzero-flags.pqfe", flagsContainer, dir,
            "test-vector-passphrase", "PostQuantum.FileEncryption conformance: reserved Flags byte set to 0x01.", 1,
            "Reserved Flags byte = 0x01. The frozen reader does not reject it (it is AAD-bound). Format-v3 candidate."));

        byte[] trailingKp = await MakePassphraseContainerAsync(
            salt: Filled(0x20, 16), iterations: 100_000, noncePrefix: Filled(0x22, 4),
            plaintext: "PostQuantum.FileEncryption conformance: trailing bytes in passphrase KeyParams."u8.ToArray(),
            flags: 0x00, keyParamsTrailing: [0xDE, 0xAD, 0xBE, 0xEF]);
        vectors.Add(Lenient("lenient-trailing-keyparams", "lenient/trailing-keyparams.pqfe", trailingKp, dir,
            "test-vector-passphrase", "PostQuantum.FileEncryption conformance: trailing bytes in passphrase KeyParams.", 1,
            "4 trailing bytes after the PBKDF2 KeyParams. The passphrase parser ignores them. Format-v3 candidate."));

        byte[] trailingFinal = [.. baseVector, 0xDE, 0xAD, 0xBE, 0xEF];
        vectors.Add(Lenient("lenient-trailing-after-final", "lenient/trailing-after-final.pqfe", trailingFinal, dir,
            "test-vector-passphrase", "PostQuantum.FileEncryption known-answer vector v2.", 1,
            "4 bytes appended after the final frame. Decryption stops at the authenticated final frame. Format-v3 candidate."));

        // Generated ONCE and pinned: KEM encapsulation is randomized, so regenerating this
        // vector would change frozen committed bytes. Reuse the committed artifacts when they
        // exist; only a brand-new corpus (or a deliberate deletion) regenerates them.
        string mrContainerPath = Path.Combine(dir, "lenient", "multi-recipient-trailing.pqfe");
        string mrKeyPath = Path.Combine(dir, "lenient", "multi-recipient-trailing.key");
        byte[] multiContainer;
        byte[] multiPrivate;
        if (File.Exists(mrContainerPath) && File.Exists(mrKeyPath))
        {
            multiContainer = await File.ReadAllBytesAsync(mrContainerPath);
            multiPrivate = await File.ReadAllBytesAsync(mrKeyPath);
        }
        else
        {
            (multiContainer, multiPrivate) = MakeMultiRecipientTrailing(
                noncePrefix: Filled(0x33, 4),
                plaintext: "PostQuantum.FileEncryption conformance: trailing block past the multi-recipient count."u8.ToArray());
        }
        await File.WriteAllBytesAsync(mrKeyPath, multiPrivate);
        vectors.Add(new ConformanceVector
        {
            Id = "lenient-multi-recipient-trailing",
            Category = "lenient",
            Expect = "accept",
            File = "lenient/multi-recipient-trailing.pqfe",
            Sha256 = Write(dir, "lenient/multi-recipient-trailing.pqfe", multiContainer),
            KeySource = 4,
            PrivateKeyFile = "lenient/multi-recipient-trailing.key",
            PlaintextUtf8 = "PostQuantum.FileEncryption conformance: trailing block past the multi-recipient count.",
            Notes = "A KeySource-4 body that declares 1 recipient but carries a second block past the count. "
                + "The reader consumes exactly the declared count and ignores the rest. Format-v3 candidate.",
        });

        var manifest = new ConformanceManifest(
            FormatVersion: 2,
            Description: "PostQuantum.FileEncryption .pqfe v2 conformance vectors. Positive vectors must "
                + "decrypt to the stated plaintext; negative vectors must be rejected (reject-format = "
                + "PqFormatException / structural; reject-decryption = PqDecryptionException / authentication); "
                + "lenient vectors pin frozen v2 reader leniencies that a future v3 profile may tighten "
                + "(docs/CONFORMANCE.md 2.2, KNOWN-GAPS.md). Regenerate with PQFE_REGEN_VECTORS=1.",
            Vectors: vectors);

        await File.WriteAllTextAsync(
            Path.Combine(dir, "manifest.json"), JsonSerializer.Serialize(manifest, Json) + "\n");
    }

    // ---- helpers ----

    private static ConformanceVector Positive(
        string id, string file, int keySource, string dir, string passphrase, string plaintext, string notes) =>
        new()
        {
            Id = id,
            Category = "positive",
            Expect = "accept",
            File = file,
            Sha256 = Sha256OfFile(Path.Combine(dir, file)),
            KeySource = keySource,
            Passphrase = passphrase,
            PlaintextUtf8 = plaintext,
            Notes = notes,
        };

    private static ConformanceVector Negative(
        string id, string expect, byte[] bytes, string dir, string notes,
        string derivedFrom = "passphrase-pbkdf2.pqfe")
    {
        string file = "negative/" + id["neg-".Length..] + (id == "neg-not-a-container" ? ".bin" : ".pqfe");
        return new ConformanceVector
        {
            Id = id,
            Category = "negative",
            Expect = expect,
            File = file,
            Sha256 = Write(dir, file, bytes),
            KeySource = 1,
            Passphrase = "test-vector-passphrase",
            DerivedFrom = derivedFrom,
            Notes = notes,
        };
    }

    private static ConformanceVector Lenient(
        string id, string file, byte[] bytes, string dir, string passphrase, string plaintext, int keySource, string notes) =>
        new()
        {
            Id = id,
            Category = "lenient",
            Expect = "accept",
            File = file,
            Sha256 = Write(dir, file, bytes),
            KeySource = keySource,
            Passphrase = passphrase,
            PlaintextUtf8 = plaintext,
            Notes = notes,
        };

    private static byte[] Mutate(byte[] source, Action<byte[]> mutation)
    {
        byte[] copy = (byte[])source.Clone();
        mutation(copy);
        return copy;
    }

    private static byte[] Filled(byte value, int length)
    {
        var b = new byte[length];
        Array.Fill(b, value);
        return b;
    }

    private static string Write(string dir, string relative, byte[] bytes)
    {
        File.WriteAllBytes(Path.Combine(dir, relative), bytes);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string Sha256OfFile(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static async Task<byte[]> MakePassphraseContainerAsync(
        byte[] salt, int iterations, byte[] noncePrefix, byte[] plaintext, byte flags, byte[]? keyParamsTrailing)
    {
        byte[] cek = Rfc2898DeriveBytes.Pbkdf2(Passphrase, salt, iterations, HashAlgorithmName.SHA256, ContainerFormat.KeyLength);

        // PBKDF2 KeyParams: KdfId(1) | SaltLen(1) | Salt | Iterations(4, BE) | optional trailing.
        var kp = new List<byte> { ContainerFormat.KdfPbkdf2HmacSha256, (byte)salt.Length };
        kp.AddRange(salt);
        Span<byte> iterBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(iterBytes, (uint)iterations);
        kp.AddRange(iterBytes.ToArray());
        if (keyParamsTrailing is not null)
        {
            kp.AddRange(keyParamsTrailing);
        }
        byte[] keyParams = kp.ToArray();

        ContainerHeader header = flags == 0
            ? ContainerHeader.Create(ContainerFormat.KeySourcePassphrase, 1024, keyParams, noncePrefix)
            : HeaderWithFlags(ContainerFormat.KeySourcePassphrase, 1024, keyParams, noncePrefix, flags);

        using var input = new MemoryStream(plaintext, writable: false);
        using var output = new MemoryStream();
        await PqContainerEngine.EncryptCoreAsync(input, output, cek, header, plaintext.Length, null, default);
        return output.ToArray();
    }

    /// <summary>Builds a header identical to <see cref="ContainerHeader.Create"/> but with a nonzero Flags byte.</summary>
    private static ContainerHeader HeaderWithFlags(byte keySource, int chunkSize, byte[] keyParams, byte[] noncePrefix, byte flags)
    {
        var bytes = new byte[ContainerFormat.FixedHeaderLength + keyParams.Length];
        var span = bytes.AsSpan();
        ContainerFormat.Magic.CopyTo(span[ContainerFormat.OffsetMagic..]);
        span[ContainerFormat.OffsetFormatVersion] = ContainerFormat.FormatVersion;
        span[ContainerFormat.OffsetAeadId] = ContainerFormat.AeadAes256Gcm;
        span[ContainerFormat.OffsetKeySource] = keySource;
        span[ContainerFormat.OffsetFlags] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(span[ContainerFormat.OffsetChunkSize..], (uint)chunkSize);
        noncePrefix.CopyTo(span[ContainerFormat.OffsetNoncePrefix..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[ContainerFormat.OffsetKeyParamsLength..], (ushort)keyParams.Length);
        keyParams.CopyTo(span[ContainerFormat.FixedHeaderLength..]);
        return new ContainerHeader(keySource, chunkSize, noncePrefix, keyParams, bytes);
    }

    private static (byte[] container, byte[] privateKey) MakeMultiRecipientTrailing(byte[] noncePrefix, byte[] plaintext)
    {
        const byte modeHybrid = 3; // frozen: Mode 3 = hybrid recipient block

        using var real = PqHybridKeyPair.Generate();
        using var stranger = PqHybridKeyPair.Generate();
        byte[] cek = RandomNumberGenerator.GetBytes(ContainerFormat.KeyLength);

        // A well-formed KeySource-4 body for exactly one recipient, then a second block appended
        // *past* the declared count — which a conforming reader consumes-and-ignores.
        byte[] body = HybridKeyEstablishment.WrapToRecipients([real.PublicKey], cek);
        byte[] strangerBlock = HybridKeyEstablishment.WrapToRecipient(stranger.PublicKey, cek);

        var keyParams = new List<byte>(body)
        {
            modeHybrid,
            (byte)(strangerBlock.Length >> 8),
            (byte)(strangerBlock.Length & 0xFF),
        };
        keyParams.AddRange(strangerBlock);

        var header = ContainerHeader.Create(ContainerFormat.KeySourceMultiRecipient, 1024, keyParams.ToArray(), noncePrefix);

        using var input = new MemoryStream(plaintext, writable: false);
        using var output = new MemoryStream();
        PqContainerEngine.EncryptCoreAsync(input, output, cek, header, plaintext.Length, null, default)
            .GetAwaiter().GetResult();
        return (output.ToArray(), real.PrivateKey.Export());
    }
}
