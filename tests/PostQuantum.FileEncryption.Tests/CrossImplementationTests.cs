using System.Text;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Cross-implementation conformance. The browser demo ships an independent Rust → WebAssembly
/// re-implementation of the <c>.pqfe</c> v2 format (<c>samples/pqfe-wasm</c>). This test pins a
/// container produced by that Rust core and proves the .NET library decrypts it — the reverse
/// direction (Rust decrypting .NET's vectors) is covered by the Rust crate's own test suite.
/// Together they keep the two implementations byte-compatible.
/// </summary>
public sealed class CrossImplementationTests
{
    private const string Passphrase = "cross-impl-passphrase";
    private const string ExpectedPlaintext = "Encrypted by the Rust/WASM core, decrypted by .NET.";

    // Produced by samples/pqfe-wasm (PBKDF2-HMAC-SHA256, AES-256-GCM, 64 KiB chunks).
    private const string RustProducedContainer =
        "UFFGRQIBAQAAAQAAikYbOgAWARDAQkJamtz3O4G2K80C5ZtbAAknwAEAAAAzWyXs57NvJnc4YxIUzCNJW+xE9IyXeQ4Tt5MFvTwMC27G/Dry6A/4bdieeZmpXSTcNsrumLpyzzeTILIOh5eGh+nR9g==";

    [Fact]
    public async Task Container_produced_by_the_rust_wasm_core_decrypts()
    {
        byte[] container = Convert.FromBase64String(RustProducedContainer);

        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, Passphrase);

        Assert.Equal(ExpectedPlaintext, Encoding.UTF8.GetString(restored.ToArray()));
    }

    [Fact]
    public async Task Rust_container_with_wrong_passphrase_fails_closed()
    {
        byte[] container = Convert.FromBase64String(RustProducedContainer);

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, "not the passphrase"));
    }
}
