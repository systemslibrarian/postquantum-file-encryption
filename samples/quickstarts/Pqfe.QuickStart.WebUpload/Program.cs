// Quickstart: an ASP.NET Core service that encrypts uploads as they stream in.
//
// The security boundary this sample keeps: the web server holds ONLY the recipient's PUBLIC
// key, so a fully compromised server can add files but cannot read a single one of them. Two
// things preserve that boundary at runtime, not just in prose:
//
//   * Plaintext never lands on the server's disk. The upload is parsed with MultipartReader
//     and streamed straight into the encryptor — not through a buffered IFormFile, whose
//     spool-to-temp-file behavior for larger uploads would put plaintext on disk.
//   * The private key is never generated or stored here. It is created OFFLINE with the
//     companion Keygen tool; only the .pub half is deployed next to this app.
//
// Provision keys OFFLINE first, on a trusted machine (never on this server):
//
//   dotnet run --project ../Pqfe.QuickStart.WebUpload.Keygen -- ./me.pub ./me.key
//   # deploy ONLY me.pub next to this app; keep me.key on the machine that decrypts uploads
//
//   dotnet run
//   curl -F "file=@report.pdf" http://localhost:5000/upload
//
// See docs/COOKBOOK.md recipes 3 and 6, and docs/ANTI-PATTERNS.md for what this deliberately
// avoids.

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using PostQuantum.FileEncryption.Hybrid;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Where to store encrypted uploads and where to find the recipient PUBLIC key. Both are
// configurable (Pqfe:StorageRoot / Pqfe:RecipientPublicKeyPath) so a real deployment — or the
// integration test — can point them wherever it likes.
string storageRoot = Path.GetFullPath(
    app.Configuration["Pqfe:StorageRoot"]
    ?? Path.Combine(app.Environment.ContentRootPath, "encrypted-uploads"));
Directory.CreateDirectory(storageRoot);

string publicKeyPath = Path.GetFullPath(
    app.Configuration["Pqfe:RecipientPublicKeyPath"]
    ?? Path.Combine(app.Environment.ContentRootPath, "me.pub"));

// Fail closed at startup if the public key is absent. This sample NEVER generates or stores a
// private key: create the identity offline and deploy only its public half here.
if (!File.Exists(publicKeyPath))
{
    throw new InvalidOperationException(
        $"Recipient public key not found at '{publicKeyPath}'. Generate a recipient identity " +
        "OFFLINE and deploy only its public half, for example:" + Environment.NewLine +
        "  dotnet run --project ../Pqfe.QuickStart.WebUpload.Keygen -- ./me.pub ./me.key" + Environment.NewLine +
        "Then set Pqfe:RecipientPublicKeyPath (or place me.pub in the content root). The private " +
        "key must never live on this server.");
}

var recipient = PqHybridPublicKey.Import(await File.ReadAllBytesAsync(publicKeyPath));
var encryptor = new PqHybridEncryptor(); // immutable and thread-safe; share one instance

app.MapPost("/upload", async (HttpRequest request, CancellationToken cancellationToken) =>
{
    // Parse the multipart body ourselves so the file section streams directly into the
    // encryptor. ASP.NET's buffered IFormFile path can spool a large upload to a temporary
    // file on disk — that would put plaintext on the server, exactly what this design forbids.
    if (!request.HasFormContentType
        || !MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
        || string.IsNullOrEmpty(contentType.Boundary.Value))
    {
        return Results.BadRequest("send one file as multipart/form-data");
    }

    string boundary = HeaderUtilities.RemoveQuotes(contentType.Boundary.Value).Value!;
    var reader = new MultipartReader(boundary, request.Body);

    for (var section = await reader.ReadNextSectionAsync(cancellationToken);
         section is not null;
         section = await reader.ReadNextSectionAsync(cancellationToken))
    {
        if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition)
            || !disposition.IsFileDisposition())
        {
            continue; // a plain form field, not the file — skip it
        }

        // Stage to a temp file, then atomically publish. A fresh GUID name means the final
        // File.Move never overwrites an existing container, and ANY failure — cancellation,
        // disk-full, an encryption error — deletes the partial staged file, so an interrupted
        // upload can never leave an incomplete .pqfe behind.
        string finalPath = Path.Combine(storageRoot, $"{Guid.NewGuid():N}.pqfe");
        string stagingPath = finalPath + ".partial";
        try
        {
            await using (var staged = new FileStream(
                stagingPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await encryptor.EncryptAsync(
                    section.Body, staged, recipient, cancellationToken: cancellationToken);
            }
            File.Move(stagingPath, finalPath); // atomic publish of a complete container
        }
        catch
        {
            TryDelete(stagingPath);
            throw; // surface the failure; never report success for a file we could not store
        }

        return Results.Ok(new { stored = Path.GetFileName(finalPath) });
    }

    return Results.BadRequest("send one file as multipart/form-data");
});

app.Run();

// Best-effort cleanup of a staged, never-published file. A leftover .partial is never a valid
// container (it was never atomically moved into place), so failing to delete it is not a
// correctness problem — but we try, so the storage directory stays tidy.
static void TryDelete(string path)
{
    try
    {
        File.Delete(path);
    }
    catch (IOException)
    {
    }
    catch (UnauthorizedAccessException)
    {
    }
}

// Exposed so the integration test can host the app in-process with WebApplicationFactory.
public partial class Program { }
