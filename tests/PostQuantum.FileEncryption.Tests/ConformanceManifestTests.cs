using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.FileEncryption.Hybrid;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Drives the machine-readable conformance corpus (<c>test-vectors/manifest.json</c>): every listed
/// vector is pinned by SHA-256 and must produce exactly the outcome the manifest declares when read
/// by the reference library. Positives decrypt to their plaintext; negatives are rejected with the
/// right exception family; the lenient corners are accepted, pinning the frozen v2 reader leniencies
/// documented in <c>docs/CONFORMANCE.md</c> 2.2. The Rust core runs the same corpus in
/// <c>samples/pqfe-wasm/tests/conformance.rs</c>, so the two implementations stay byte-compatible.
///
/// A hash failure means a committed artifact drifted — revert it; never update the hash inside 1.x.
/// Regenerate the corpus with the <see cref="ConformanceVectorGenerator"/> tool (PQFE_REGEN_VECTORS=1).
/// </summary>
public sealed class ConformanceManifestTests
{
    public static IEnumerable<object[]> AllVectors()
    {
        // Guarded so test discovery never throws before the corpus is first generated.
        string path = Path.Combine(FindRepositoryRoot(), "test-vectors", "manifest.json");
        if (!File.Exists(path))
        {
            yield break;
        }
        foreach (ConformanceVector v in LoadManifest().Vectors)
        {
            yield return new object[] { v.Id };
        }
    }

    [Fact]
    public void Manifest_is_present_and_covers_all_three_categories()
    {
        var manifest = LoadManifest();
        Assert.Equal(2, manifest.FormatVersion);
        Assert.Contains(manifest.Vectors, v => v.Category == "positive");
        Assert.Contains(manifest.Vectors, v => v.Category == "negative");
        Assert.Contains(manifest.Vectors, v => v.Category == "lenient");
    }

    [Theory]
    [MemberData(nameof(AllVectors))]
    public async Task Vector_is_pinned_and_produces_its_declared_outcome(string id)
    {
        string dir = Path.Combine(FindRepositoryRoot(), "test-vectors");
        ConformanceVector v = LoadManifest().Vectors.Single(x => x.Id == id);

        byte[] bytes = await File.ReadAllBytesAsync(Path.Combine(dir, v.File));
        Assert.Equal(v.Sha256, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());

        switch (v.Expect)
        {
            case "accept":
                Assert.Equal(v.PlaintextUtf8, Encoding.UTF8.GetString(await DecryptAsync(v, bytes, dir)));
                break;
            case "reject-format":
                await Assert.ThrowsAsync<PqFormatException>(() => DecryptAsync(v, bytes, dir));
                break;
            case "reject-decryption":
                await Assert.ThrowsAsync<PqDecryptionException>(() => DecryptAsync(v, bytes, dir));
                break;
            default:
                Assert.Fail($"Unknown expect value '{v.Expect}' for vector '{id}'.");
                break;
        }
    }

    private static async Task<byte[]> DecryptAsync(ConformanceVector v, byte[] container, string dir)
    {
        if (v.PrivateKeyFile is not null)
        {
            byte[] keyBytes = await File.ReadAllBytesAsync(Path.Combine(dir, v.PrivateKeyFile));
            using var key = PqHybridPrivateKey.Import(keyBytes);
            return await new PqHybridDecryptor().DecryptBytesAsync(container, key);
        }

        return await new PqFileDecryptor().DecryptBytesAsync(container, v.Passphrase!);
    }

    private static ConformanceManifest LoadManifest()
    {
        string path = Path.Combine(FindRepositoryRoot(), "test-vectors", "manifest.json");
        return JsonSerializer.Deserialize<ConformanceManifest>(
            File.ReadAllText(path), ConformanceVectorGenerator.Json)
            ?? throw new InvalidOperationException($"Could not deserialize {path}.");
    }

    internal static string FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "test-vectors")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName
            ?? throw new InvalidOperationException(
                $"No 'test-vectors' directory found above {AppContext.BaseDirectory}.");
    }
}
