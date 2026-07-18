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
    await File.WriteAllBytesAsync(publicOut, keyPair.PublicKey.Export());
    // ExportEncrypted (not Export): the private key is written only as an authenticated,
    // Argon2id-hardened PQKF file that fails closed on a wrong passphrase or any tampering.
    await File.WriteAllBytesAsync(privateOut, keyPair.PrivateKey.ExportEncrypted(passphrase));
}
finally
{
    Array.Clear(passphrase); // zero our copy of the passphrase
}

Console.WriteLine($"Wrote public key  -> {publicOut}   (deploy this with the web app)");
Console.WriteLine($"Wrote private key -> {privateOut}  (keep secret; never on the web server)");
return 0;

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
