// Quickstart: an ASP.NET Core service that encrypts uploads as they stream in.
//
// The design decision that matters: the web server holds only the recipient PUBLIC key, so a
// fully compromised web server can add files but cannot read a single one of them. Plaintext
// never lands on the server's disk; encryption streams in constant memory regardless of file
// size. Decryption happens elsewhere, by whoever holds the private key.
//
//   dotnet run
//   curl -F "file=@report.pdf" http://localhost:5000/upload
//
// See docs/COOKBOOK.md recipes 3 and 6, and docs/ANTI-PATTERNS.md for what this deliberately
// avoids.

using PostQuantum.FileEncryption.Hybrid;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

string storageRoot = Path.Combine(app.Environment.ContentRootPath, "encrypted-uploads");
Directory.CreateDirectory(storageRoot);

// Demo only: generate a key pair on first run so the sample is runnable out of the box.
// In production the private key is created OFFLINE and only me.pub is deployed with the app;
// see `pqfe keygen --encrypt` and COOKBOOK recipe 3.
string publicKeyPath = Path.Combine(app.Environment.ContentRootPath, "me.pub");
if (!File.Exists(publicKeyPath))
{
    using var demoKeys = PqHybridKeyPair.Generate();
    await File.WriteAllBytesAsync(publicKeyPath, demoKeys.PublicKey.Export());
    await File.WriteAllBytesAsync(
        Path.Combine(app.Environment.ContentRootPath, "demo-private.key"),
        demoKeys.PrivateKey.ExportEncrypted("demo-only passphrase - do not deploy this pattern"));
    Console.Error.WriteLine("Generated a DEMO key pair; in production, keygen happens offline.");
}
var recipient = PqHybridPublicKey.Import(await File.ReadAllBytesAsync(publicKeyPath));
var encryptor = new PqHybridEncryptor(); // thread-safe; share one instance

app.MapPost("/upload", async (HttpRequest request, CancellationToken cancellationToken) =>
{
    IFormFileCollection files = (await request.ReadFormAsync(cancellationToken)).Files;
    if (files.Count == 0)
    {
        return Results.BadRequest("send one file as multipart/form-data");
    }
    IFormFile file = files[0];

    string storagePath = Path.Combine(storageRoot, $"{Guid.NewGuid():N}.pqfe");
    try
    {
        await using Stream upload = file.OpenReadStream();
        await using var output = File.Create(storagePath);
        await encryptor.EncryptToAsync(
            upload, output, [recipient], file.Length, null, cancellationToken);
    }
    catch (OperationCanceledException)
    {
        // Client disconnected mid-upload: never keep a half-written container.
        File.Delete(storagePath);
        throw;
    }

    return Results.Ok(new { stored = Path.GetFileName(storagePath) });
});

app.Run();
