// Offline recipient-key generator for the WebUpload quickstart.
//
// Run this on a TRUSTED machine — never on the web server. It writes:
//   * <public-out>  : the recipient PUBLIC key. Deploy this next to the web app; it is the
//                     only key material the server ever holds.
//   * <private-out> : the recipient PRIVATE key, as a passphrase-encrypted PQKF file. Keep it
//                     secret, on the machine that will DECRYPT uploads — never on the server.
//
//   dotnet run -- ./me.pub ./me.key
//
// The private-key file is passphrase-protected. Provide the passphrase via the PQFE_PASS
// environment variable, or you will be prompted for it. The private key is written ONLY in the
// encrypted PQKF form (ExportEncrypted), never as raw Export() bytes.
//
// Both outputs are opened CreateNew: overwriting an existing key pair would permanently orphan
// every container already encrypted to the old public key, so an existing file is a hard error,
// never a silent replace. The private key is written first (owner-only permissions on Unix); if
// the public half then fails to write, the private file is removed so no mismatched half-pair
// is left behind.

using System.Security.Cryptography;
using PostQuantum.FileEncryption.Hybrid;

if (args.Length != 2)
{
    await Console.Error.WriteLineAsync(
        "usage: <public-key-out> <encrypted-private-key-out>");
    return 64;
}

string publicOut = args[0];
string privateOut = args[1];

char[]? passphrase = ReadPassphrase();
if (passphrase is null || passphrase.Length == 0)
{
    await Console.Error.WriteLineAsync(
        "A passphrase is required to protect the private-key file.");
    return 64;
}

try
{
    using var keyPair = PqHybridKeyPair.Generate();
    // ExportEncrypted (not Export): the private key is written only as an authenticated,
    // Argon2id-hardened PQKF file that fails closed on a wrong passphrase or any tampering.
    await WriteNewFileAsync(privateOut, keyPair.PrivateKey.ExportEncrypted(passphrase), ownerOnly: true);
    try
    {
        await WriteNewFileAsync(publicOut, keyPair.PublicKey.Export(), ownerOnly: false);
    }
    catch
    {
        // Never leave a private key whose public half failed to materialize.
        try { File.Delete(privateOut); } catch (IOException) { }
        throw;
    }
}
catch (IOException ex)
{
    await Console.Error.WriteLineAsync(
        $"error: {ex.Message}\nRefusing to overwrite an existing key file — replacing a key pair " +
        "would permanently orphan every upload already encrypted to the old public key. " +
        "Move the existing files aside first if you really mean to rotate.");
    return 73; // sysexits.h EX_CANTCREAT
}
finally
{
    Array.Clear(passphrase); // zero our copy of the passphrase
}

Console.WriteLine($"Wrote public key  -> {publicOut}   (deploy this with the web app)");
Console.WriteLine($"Wrote private key -> {privateOut}  (keep secret; never on the web server)");
return 0;

static async Task WriteNewFileAsync(string path, byte[] bytes, bool ownerOnly)
{
    var options = new FileStreamOptions
    {
        Mode = FileMode.CreateNew, // an existing file is an error, never a silent overwrite
        Access = FileAccess.Write,
        Share = FileShare.None,
    };
    if (ownerOnly && !OperatingSystem.IsWindows())
    {
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite; // 0600, like ssh-keygen
    }
    await using var stream = new FileStream(path, options);
    await stream.WriteAsync(bytes);
}

static char[]? ReadPassphrase()
{
    string? fromEnv = Environment.GetEnvironmentVariable("PQFE_PASS");
    if (!string.IsNullOrEmpty(fromEnv))
    {
        return fromEnv.ToCharArray();
    }

    Console.Error.Write("Passphrase for the private-key file: ");
    return Console.ReadLine()?.ToCharArray();
}
