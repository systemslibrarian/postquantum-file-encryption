using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Hybrid;

// CI-only cross-implementation driver mirroring samples/pqfe-wasm/examples/pqfe_io.rs, so the
// interop job can round-trip hybrid recipient containers between .NET and Rust. Key files hold
// the raw PqHybridPublicKey/PqHybridPrivateKey.Export() bytes (1216 / 2432).
//
//   pqfe-hybrid-interop keygen-hybrid  <pubfile> <privfile>
//   pqfe-hybrid-interop encrypt-hybrid <in> <out> <pub> [pub...]
//   pqfe-hybrid-interop decrypt-hybrid <in> <out> <priv>

return await Run(args).ConfigureAwait(false);

static async Task<int> Run(string[] args)
{
    switch (args.Length >= 1 ? args[0] : "")
    {
        case "keygen-hybrid" when args.Length == 3:
        {
            using var keyPair = PqHybridKeyPair.Generate();
            await File.WriteAllBytesAsync(args[1], keyPair.PublicKey.Export()).ConfigureAwait(false);
            await File.WriteAllBytesAsync(args[2], keyPair.PrivateKey.Export()).ConfigureAwait(false);
            return 0;
        }

        case "encrypt-hybrid" when args.Length >= 4:
        {
            byte[] input = await File.ReadAllBytesAsync(args[1]).ConfigureAwait(false);
            var recipients = new List<PqHybridPublicKey>();
            for (int i = 3; i < args.Length; i++)
            {
                recipients.Add(PqHybridPublicKey.Import(
                    await File.ReadAllBytesAsync(args[i]).ConfigureAwait(false)));
            }

            byte[] container = await new PqHybridEncryptor()
                .EncryptBytesToAsync(input, recipients).ConfigureAwait(false);
            await File.WriteAllBytesAsync(args[2], container).ConfigureAwait(false);
            return 0;
        }

        case "decrypt-hybrid" when args.Length == 4:
        {
            byte[] container = await File.ReadAllBytesAsync(args[1]).ConfigureAwait(false);
            using var key = PqHybridPrivateKey.Import(
                await File.ReadAllBytesAsync(args[3]).ConfigureAwait(false));
            try
            {
                byte[] plaintext = await new PqHybridDecryptor()
                    .DecryptBytesAsync(container, key).ConfigureAwait(false);
                await File.WriteAllBytesAsync(args[2], plaintext).ConfigureAwait(false);
                return 0;
            }
            catch (PqDecryptionException e)
            {
                await Console.Error.WriteLineAsync($"error: decryption failed: {e.Message}")
                    .ConfigureAwait(false);
                return 65;
            }
        }

        default:
            await Console.Error.WriteLineAsync(
                "usage: pqfe-hybrid-interop <keygen-hybrid|encrypt-hybrid|decrypt-hybrid> ...")
                .ConfigureAwait(false);
            return 64;
    }
}
