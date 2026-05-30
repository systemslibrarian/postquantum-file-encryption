using System.Text;
using PostQuantum.FileEncryption.Internal;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Byte-exact conformance. With a fixed salt and nonce prefix the container is fully
/// deterministic, so the .NET library and the Rust/WASM core must emit the <em>identical</em>
/// bytes. The same pinned value is asserted by <c>samples/pqfe-wasm/tests/vectors.rs</c> — that
/// cross-check is the strongest guarantee the two implementations agree on the format.
/// </summary>
public sealed class DeterministicVectorTests
{
    private const string Passphrase = "deterministic-conformance";
    private const string Plaintext = "Deterministic conformance vector - byte for byte.";
    private const int Iterations = 120_000;
    private const int ChunkSize = 1024;

    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
    private static readonly byte[] NoncePrefix = { 0xA1, 0xB2, 0xC3, 0xD4 };

    // Pinned byte-exact container; the Rust core produces these exact bytes for the same inputs.
    private const string Vector =
        "UFFGRQIBAQAAAAQAobLD1AAWARAAAQIDBAUGBwgJCgsMDQ4PAAHUwAEAAAAx8LbT/vUWhAJzxG27tIWQK9TfelTH70vWt+4CuWNvi58E0J1kT46rSZnQgLQx7ndsXtTEuK5a8PFd/Geog1+9mN4=";

    private static async Task<byte[]> EncryptDeterministicAsync()
    {
        var options = new PqEncryptionOptions { Pbkdf2Iterations = Iterations, ChunkSizeBytes = ChunkSize, SaltSizeBytes = Salt.Length };
        using var input = new MemoryStream(Encoding.ASCII.GetBytes(Plaintext));
        using var output = new MemoryStream();
        await PqContainer.EncryptPassphraseAsync(
            input, output, Encoding.ASCII.GetBytes(Passphrase), options,
            null, null, default, Salt, NoncePrefix);
        return output.ToArray();
    }

    [Fact]
    public async Task Deterministic_encryption_matches_the_pinned_vector()
    {
        Assert.Equal(Vector, Convert.ToBase64String(await EncryptDeterministicAsync()));
    }

    [Fact]
    public async Task Pinned_vector_decrypts_to_the_known_plaintext()
    {
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(Convert.FromBase64String(Vector), Passphrase);
        Assert.Equal(Plaintext, Encoding.ASCII.GetString(restored));
    }
}
