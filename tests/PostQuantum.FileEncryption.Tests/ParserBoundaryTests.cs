using System.Buffers.Binary;
using PostQuantum.FileEncryption.Internal;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Exact-boundary tests for the untrusted-header parsers, written from a mutation-testing run
/// (Stryker, 2026-07-02): every case here kills a mutant that survived the suite — an
/// off-by-one or flipped conjunction in these range checks would previously have shipped
/// undetected. The pattern throughout: the first illegal value on each side of a bound is
/// rejected with <see cref="PqFormatException"/>, and the exact legal bound is accepted.
/// </summary>
public sealed class ParserBoundaryTests
{
    private static readonly byte[] Passphrase = "boundary-test-passphrase"u8.ToArray();

    private static Task<byte[]> DeriveAsync(byte[] keyParams, PqDecryptionLimits? limits = null)
    {
        var header = ContainerHeader.Create(ContainerFormat.KeySourcePassphrase, 1024, keyParams);
        return KeyEstablishment.DerivePassphraseKeyAsync(Passphrase, header, limits ?? PqDecryptionLimits.Default);
    }

    private static byte[] Pbkdf2Params(byte declaredSaltLength, int actualSaltBytes, uint iterations)
    {
        byte[] p = new byte[2 + actualSaltBytes + 4];
        p[0] = ContainerFormat.KdfPbkdf2HmacSha256;
        p[1] = declaredSaltLength;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(2 + actualSaltBytes), iterations);
        return p;
    }

    private static byte[] Argon2Params(uint memoryKiB, uint iterations, byte parallelism)
    {
        byte[] p = new byte[2 + 16 + 9];
        p[0] = ContainerFormat.KdfArgon2id;
        p[1] = 16;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(18), memoryKiB);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(22), iterations);
        p[26] = parallelism;
        return p;
    }

    // ------------------------------------------------------------------ KeyParams structure

    [Fact]
    public async Task Truncated_key_params_are_rejected()
    {
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync([]));
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync([ContainerFormat.KdfPbkdf2HmacSha256]));
        // PBKDF2 params that end inside the 4-byte iteration count.
        await Assert.ThrowsAsync<PqFormatException>(() =>
            DeriveAsync([ContainerFormat.KdfPbkdf2HmacSha256, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        // Argon2id params that end inside the 9-byte cost block.
        await Assert.ThrowsAsync<PqFormatException>(() =>
            DeriveAsync([ContainerFormat.KdfArgon2id, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    [Fact]
    public async Task Unknown_kdf_identifier_is_rejected()
    {
        byte[] p = Pbkdf2Params(8, 8, 100_000);
        p[0] = 99;
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(p));
    }

    // ------------------------------------------------------------------ salt bounds

    [Fact]
    public async Task Salt_below_the_minimum_is_rejected_and_the_minimum_is_accepted()
    {
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Pbkdf2Params(7, 7, 100_000)));
        // A salt shorter than its declared length (header lies about what follows).
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Pbkdf2Params(200, 16, 100_000)));

        byte[] key = await DeriveAsync(Pbkdf2Params(8, 8, 100_000));
        Assert.Equal(32, key.Length);
    }

    // ------------------------------------------------------------------ PBKDF2 bounds

    [Fact]
    public async Task Pbkdf2_iterations_below_the_format_minimum_are_rejected()
    {
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Pbkdf2Params(16, 16, 99_999)));
    }

    [Fact]
    public async Task Pbkdf2_iterations_exactly_at_a_decryptor_limit_are_accepted_and_one_above_rejected()
    {
        var limits = new PqDecryptionLimits { MaxPbkdf2Iterations = 100_000 };

        byte[] key = await DeriveAsync(Pbkdf2Params(16, 16, 100_000), limits);
        Assert.Equal(32, key.Length);

        await Assert.ThrowsAsync<PqFormatException>(() =>
            DeriveAsync(Pbkdf2Params(16, 16, 100_001), limits));
    }

    // ------------------------------------------------------------------ Argon2id bounds

    [Fact]
    public async Task Argon2id_parameters_below_the_format_minimums_are_rejected()
    {
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(8 * 1024 - 1, 1, 1)));
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(8 * 1024, 0, 1)));
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(8 * 1024, 1, 0)));
    }

    [Fact]
    public async Task Argon2id_parameters_above_the_format_maximums_are_rejected()
    {
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(2_097_153, 1, 1)));
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(8 * 1024, 10_001, 1)));
    }

    [Fact]
    public async Task Argon2id_exact_minimums_are_accepted()
    {
        // 8 MiB, 1 pass, 1 lane — every value sits exactly on its lower bound.
        byte[] key = await DeriveAsync(Argon2Params(8 * 1024, 1, 1));
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public async Task Argon2id_costs_exactly_at_a_decryptor_limit_are_accepted_and_one_above_rejected()
    {
        var limits = new PqDecryptionLimits { MaxArgon2MemoryKiB = 16 * 1024, MaxArgon2Iterations = 2 };

        byte[] key = await DeriveAsync(Argon2Params(16 * 1024, 2, 1), limits);
        Assert.Equal(32, key.Length);

        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(16 * 1024 + 1, 2, 1), limits));
        await Assert.ThrowsAsync<PqFormatException>(() => DeriveAsync(Argon2Params(16 * 1024, 3, 1), limits));
    }

    // ------------------------------------------------------------------ fixed-header parsing

    private static byte[] ValidHeaderBytes() =>
        (byte[])ContainerHeader.Create(
            ContainerFormat.KeySourcePassphrase, 1024, Pbkdf2Params(16, 16, 100_000)).HeaderBytes.Clone();

    [Fact]
    public void Unknown_aead_and_key_source_identifiers_are_rejected()
    {
        byte[] aead = ValidHeaderBytes();
        aead[ContainerFormat.OffsetAeadId] = 9;
        Assert.Throws<PqFormatException>(() => ContainerHeader.Parse(aead));

        byte[] keySource = ValidHeaderBytes();
        keySource[ContainerFormat.OffsetKeySource] = 9;
        Assert.Throws<PqFormatException>(() => ContainerHeader.Parse(keySource));
    }

    [Fact]
    public void Out_of_range_chunk_sizes_are_rejected_and_the_bounds_are_accepted()
    {
        byte[] tooSmall = ValidHeaderBytes();
        BinaryPrimitives.WriteUInt32BigEndian(tooSmall.AsSpan(ContainerFormat.OffsetChunkSize), 1023);
        Assert.Throws<PqFormatException>(() => ContainerHeader.Parse(tooSmall));

        byte[] tooLarge = ValidHeaderBytes();
        BinaryPrimitives.WriteUInt32BigEndian(tooLarge.AsSpan(ContainerFormat.OffsetChunkSize), 16 * 1024 * 1024 + 1);
        Assert.Throws<PqFormatException>(() => ContainerHeader.Parse(tooLarge));

        foreach (uint bound in new uint[] { 1024, 16 * 1024 * 1024 })
        {
            byte[] atBound = ValidHeaderBytes();
            BinaryPrimitives.WriteUInt32BigEndian(atBound.AsSpan(ContainerFormat.OffsetChunkSize), bound);
            Assert.Equal((int)bound, ContainerHeader.Parse(atBound).ChunkSize);
        }
    }

    [Fact]
    public void Header_whose_declared_key_params_length_disagrees_with_its_size_is_rejected()
    {
        byte[] header = ValidHeaderBytes();
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(ContainerFormat.OffsetKeyParamsLength), 1);
        Assert.Throws<PqFormatException>(() => ContainerHeader.Parse(header));
    }

    [Fact]
    public void Key_params_block_at_the_maximum_length_is_accepted_and_one_above_rejected()
    {
        Assert.NotNull(ContainerHeader.Create(
            ContainerFormat.KeySourceKeyProvider, 1024, new byte[ushort.MaxValue]));
        Assert.Throws<ArgumentException>(() => ContainerHeader.Create(
            ContainerFormat.KeySourceKeyProvider, 1024, new byte[ushort.MaxValue + 1]));
    }
}

/// <summary>
/// Lifecycle pins for <see cref="LocalKekContentKeyProvider"/>, also from the mutation run:
/// use-after-dispose must surface as <see cref="ObjectDisposedException"/> on every operation,
/// and each wrap must draw a fresh random nonce.
/// </summary>
public sealed class LocalKekLifecycleTests
{
    [Fact]
    public async Task Disposed_provider_rejects_every_operation()
    {
        var provider = LocalKekContentKeyProvider.Generate();
        (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync();
        provider.Dispose();
        provider.Dispose(); // double-dispose is harmless

        await Assert.ThrowsAsync<ObjectDisposedException>(() => provider.WrapNewKeyAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => provider.UnwrapKeyAsync(wrapInfo));
        Assert.Throws<ObjectDisposedException>(() => provider.ExportKek());

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(contentKey);
    }

    [Fact]
    public async Task Each_wrap_uses_a_fresh_nonce()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        (byte[] key1, byte[] wrap1) = await provider.WrapNewKeyAsync();
        (byte[] key2, byte[] wrap2) = await provider.WrapNewKeyAsync();

        // wrapInfo layout: Nonce(12) ‖ Tag(16) ‖ WrappedKey(32) — the nonces must differ, or
        // two wraps under the same KEK would reuse a GCM nonce.
        Assert.False(wrap1.AsSpan(0, 12).SequenceEqual(wrap2.AsSpan(0, 12)));

        System.Security.Cryptography.CryptographicOperations.ZeroMemory(key1);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(key2);
    }

    [Fact]
    public async Task Cancellation_is_observed_before_any_work()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.WrapNewKeyAsync(cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.UnwrapKeyAsync(new byte[60], cts.Token));
    }
}
