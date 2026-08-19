using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc.Testing;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Hybrid;
using Xunit;

namespace Pqfe.QuickStart.WebUpload.Tests;

/// <summary>
/// Proves the WebUpload quickstart actually delivers the security property it advertises: the
/// server holds only the recipient PUBLIC key, plaintext never reaches its disk, and a failed
/// or file-less upload leaves nothing behind. The recipient PRIVATE key lives only in the test
/// (standing in for the external machine that decrypts) — never inside the hosted app.
/// </summary>
public sealed class WebUploadTests : IDisposable
{
    private readonly string _workDir;
    private readonly string _storageRoot;
    private readonly string _publicKeyPath;
    private readonly PqHybridPrivateKey _recipientPrivateKey;

    public WebUploadTests()
    {
        _workDir = Path.Combine(
            Path.GetTempPath(), "pqfe-webupload-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workDir);
        _storageRoot = Path.Combine(_workDir, "encrypted-uploads");
        _publicKeyPath = Path.Combine(_workDir, "me.pub");

        // Provision keys the way an operator would OFFLINE: only the public half is handed to
        // the web app. The private half stays here, standing in for the external recipient.
        using var keyPair = PqHybridKeyPair.Generate();
        File.WriteAllBytes(_publicKeyPath, keyPair.PublicKey.Export());
        _recipientPrivateKey = PqHybridPrivateKey.Import(keyPair.PrivateKey.Export());
    }

    private WebApplicationFactory<Program> CreateApp() =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            b.UseSetting("Pqfe:RecipientPublicKeyPath", _publicKeyPath)
             .UseSetting("Pqfe:StorageRoot", _storageRoot));

    [Fact]
    public async Task Upload_streams_ciphertext_that_only_the_private_key_can_open()
    {
        // A payload well above ASP.NET's 64 KiB IFormFile spool threshold: the old buffered
        // path could have written this plaintext to a temp file on the server's disk.
        byte[] plaintext = RandomNumberGenerator.GetBytes(1_500_000);

        using var app = CreateApp();
        using var client = app.CreateClient();
        using var content = new MultipartFormDataContent
        {
            { new ByteArrayContent(plaintext), "file", "report.bin" },
        };

        using var response = await client.PostAsync("/upload", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Exactly one finished container, and no leftover staging file.
        string[] produced = Directory.GetFiles(_storageRoot);
        Assert.Single(produced);
        Assert.EndsWith(".pqfe", produced[0], StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(_storageRoot, "*.partial"));

        byte[] container = await File.ReadAllBytesAsync(produced[0]);
        // It is a real .pqfe container (magic "PQFE"), not the plaintext echoed to disk.
        Assert.Equal("PQFE"u8.ToArray(), container[..4]);

        // The web app never held the private key; decryption succeeds only here, with it.
        byte[] recovered = await new PqHybridDecryptor()
            .DecryptBytesAsync(container, _recipientPrivateKey);
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public async Task A_stranger_key_cannot_open_an_uploaded_container()
    {
        byte[] plaintext = RandomNumberGenerator.GetBytes(4096);

        using var app = CreateApp();
        using var client = app.CreateClient();
        using var content = new MultipartFormDataContent
        {
            { new ByteArrayContent(plaintext), "file", "x.bin" },
        };
        using var response = await client.PostAsync("/upload", content);
        response.EnsureSuccessStatusCode();

        byte[] container = await File.ReadAllBytesAsync(Directory.GetFiles(_storageRoot)[0]);
        using var stranger = PqHybridKeyPair.Generate();
        await Assert.ThrowsAsync<PqDecryptionException>(
            () => new PqHybridDecryptor().DecryptBytesAsync(container, stranger.PrivateKey));
    }

    [Fact]
    public async Task Upload_with_no_file_section_is_rejected_and_writes_nothing()
    {
        using var app = CreateApp();
        using var client = app.CreateClient();
        using var content = new MultipartFormDataContent
        {
            { new StringContent("just a form field"), "notafile" },
        };

        using var response = await client.PostAsync("/upload", content);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(Directory.GetFiles(_storageRoot));
    }

    public void Dispose()
    {
        _recipientPrivateKey.Dispose();
        try
        {
            Directory.Delete(_workDir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
