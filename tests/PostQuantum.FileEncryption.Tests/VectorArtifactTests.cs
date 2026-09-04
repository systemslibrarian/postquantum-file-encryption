using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Guards the committed vector artifacts (<c>test-vectors/</c> at the repository root)
/// against drift: those bytes are the published known-answer vectors and are frozen with
/// the v2 format for the entire 1.x line. A failure here means an artifact was edited or
/// regenerated — revert the artifact; never update these hashes inside 1.x.
/// </summary>
public sealed class VectorArtifactTests
{
    [Theory]
    [InlineData("passphrase-pbkdf2.pqfe", "AB32CC1D2F5F673D77D80FC2F45307ABE4A33A35552F2B5C677A9C5818718547")]
    [InlineData("passphrase-argon2id.pqfe", "4E165D1238FCAD436BAD8B7CD72072B9196E4492AADDFCDDFBC82029F0ECA4EE")]
    [InlineData("passphrase-pbkdf2-rustcore.pqfe", "B428F6492C78FE03B8B3197872E60BD737764BE066CDADDAB594F06F18E6ADE6")]
    [InlineData("passphrase-pbkdf2-multichunk.pqfe", "008543AB899A427A33100F1B865B54C5EF0426834B8E7B696EEFFC9B97EA886A")]
    [InlineData("keyfile.pqkf", "EEDA08E328B028E69F87145642C7898C72BE83E410EBFD595F0B2B50FD9BFB38")]
    [InlineData("hybrid-recipient.pqfe", "A16FF8DB3DAD6A50D9A81CEE5A97CE26D875C8DCE80A00C93DD7516F080D31DE")]
    public void Committed_vector_artifact_is_byte_identical(string fileName, string expectedSha256)
    {
        string path = Path.Combine(FindRepositoryRoot(), "test-vectors", fileName);
        byte[] bytes = File.ReadAllBytes(path);

        Assert.Equal(expectedSha256, Convert.ToHexString(SHA256.HashData(bytes)));
    }

    [Fact]
    public void Sha256sums_file_matches_the_committed_artifacts_and_lists_them_all()
    {
        // test-vectors/SHA256SUMS exists so third-party implementers can verify their copy of
        // the corpus; until this test it was itself verified by nothing and could silently
        // drift from the artifacts it describes.
        string dir = Path.Combine(FindRepositoryRoot(), "test-vectors");
        var listed = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (string line in File.ReadAllLines(Path.Combine(dir, "SHA256SUMS")))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            // "<hex-sha256> *<filename>" — the sha256sum binary-mode format.
            int sep = line.IndexOf(" *", StringComparison.Ordinal);
            Assert.True(sep == 64, $"Unparseable SHA256SUMS line: '{line}'");
            listed[line[(sep + 2)..]] = line[..sep];
        }

        foreach ((string file, string expected) in listed)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(dir, file));
            Assert.Equal(expected, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
        }

        // Every top-level committed artifact must be listed (negatives/lenients are pinned by
        // manifest.json instead).
        foreach (string path in Directory.EnumerateFiles(dir))
        {
            string name = Path.GetFileName(path);
            if (name.EndsWith(".pqfe", StringComparison.Ordinal) || name.EndsWith(".pqkf", StringComparison.Ordinal))
            {
                Assert.True(listed.ContainsKey(name), $"'{name}' is missing from SHA256SUMS");
            }
        }
    }

    private static string FindRepositoryRoot()
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
