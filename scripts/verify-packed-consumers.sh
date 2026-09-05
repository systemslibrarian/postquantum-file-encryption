#!/usr/bin/env bash
# Packed-consumer verification: prove the NuGet packages work AS CONSUMERS RECEIVE THEM.
#
# The solution build proves source compatibility; it cannot catch bad package assets, broken
# dependency pins, analyzer packaging mistakes, or tool-payload failures. This script packs
# all nine lockstep packages into a local feed, then:
#
#   1. builds a clean multi-targeted (net8.0 + net10.0) console consumer that references the
#      eight library/analyzer packages FROM THE FEED (no project references anywhere),
#   2. asserts the packed analyzers actually load and fire (PQFE101 on a literal passphrase),
#   3. runs a full journey on BOTH target frameworks: passphrase round trip under Untrusted
#      limits, hybrid multi-recipient round trip, PQKF private-key export/import, public-key
#      fingerprints, detached sign + verify (including a tamper rejection), and DI resolution,
#   4. installs the packed `pqfe` dotnet tool from the feed and drives it end to end:
#      passphrase encrypt/decrypt, recipient keygen/encrypt/decrypt, sign/verify, and a
#      wrong-passphrase rejection with the documented exit code (65).
#
# Run locally:  bash scripts/verify-packed-consumers.sh
# CI:           .github/workflows/packed-consumers.yml
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
REPO="$PWD"

VERSION="$(sed -n 's/.*<Version>\([^<]*\)<\/Version>.*/\1/p' src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj | head -n1)"
[ -n "$VERSION" ] || { echo "could not read <Version>" >&2; exit 2; }
# A distinct prerelease version: the published $VERSION may already sit in the NuGet global
# cache, and NuGet would silently serve that cached copy instead of the freshly packed one —
# masking exactly the packaging regressions this script exists to catch.
LOCALVER="$VERSION-packed"
echo "==> Verifying packed consumers for version $VERSION (packed as $LOCALVER)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FEED="$WORK/feed"
mkdir -p "$FEED"
# Hermetic: nothing from this machine's global package cache can leak into the run.
export NUGET_PACKAGES="$WORK/nuget-packages"

echo "==> Packing all nine packages into the local feed"
for proj in \
  src/PostQuantum.FileEncryption \
  src/PostQuantum.FileEncryption.Hybrid \
  src/PostQuantum.FileEncryption.Signing \
  src/PostQuantum.FileEncryption.Aws \
  src/PostQuantum.FileEncryption.AzureKeyVault \
  src/PostQuantum.FileEncryption.Gcp \
  src/PostQuantum.FileEncryption.Extensions.DependencyInjection \
  src/PostQuantum.FileEncryption.Analyzers \
  samples/Pqfe.Cli; do
  dotnet pack "$proj" -c Release -o "$FEED" --nologo -v q -p:Version="$LOCALVER"
done

CONSUMER="$WORK/consumer"
mkdir -p "$CONSUMER"
cd "$CONSUMER"

cat > nuget.config <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local-feed" value="$FEED" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF

cat > Consumer.csproj <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="PostQuantum.FileEncryption" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Hybrid" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Signing" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Aws" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.AzureKeyVault" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Gcp" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Extensions.DependencyInjection" Version="$LOCALVER" />
    <PackageReference Include="PostQuantum.FileEncryption.Analyzers" Version="$LOCALVER" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection" Version="8.0.1" />
  </ItemGroup>
</Project>
EOF

cat > Program.cs <<'EOF'
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Signing;

// Deliberately a literal: the packed analyzer must load from the .nupkg and flag it (PQFE101),
// which the driving script asserts on the build output.
const string Passphrase = "packed-consumer-journey-passphrase";

byte[] secret = RandomNumberGenerator.GetBytes(4096);
var options = new PqEncryptionOptions { Pbkdf2Iterations = 100_000, ChunkSizeBytes = 1024 };

// 1. Passphrase round trip under Untrusted limits.
byte[] container = await new PqFileEncryptor(options).EncryptBytesAsync(secret, Passphrase);
byte[] restored = await new PqFileDecryptor(PqDecryptionLimits.Untrusted).DecryptBytesAsync(container, Passphrase);
if (!restored.AsSpan().SequenceEqual(secret)) throw new Exception("passphrase round trip failed");

// 2. Hybrid multi-recipient round trip + PQKF export/import + fingerprint.
using var alice = PqHybridKeyPair.Generate();
using var bob = PqHybridKeyPair.Generate();
byte[] hybrid = await new PqHybridEncryptor(options).EncryptBytesToAsync(secret, [alice.PublicKey, bob.PublicKey]);
byte[] viaBob = await new PqHybridDecryptor(PqDecryptionLimits.Untrusted).DecryptBytesAsync(hybrid, bob.PrivateKey);
if (!viaBob.AsSpan().SequenceEqual(secret)) throw new Exception("hybrid round trip failed");

byte[] keyFile = alice.PrivateKey.ExportEncrypted(Passphrase);
using (var reimported = PqHybridPrivateKey.ImportEncrypted(keyFile, Passphrase, PqDecryptionLimits.Untrusted))
{
    byte[] viaAlice = await new PqHybridDecryptor().DecryptBytesAsync(hybrid, reimported);
    if (!viaAlice.AsSpan().SequenceEqual(secret)) throw new Exception("PQKF import round trip failed");
}
if (!alice.PublicKey.GetFingerprint().StartsWith("pqfp1:", StringComparison.Ordinal))
    throw new Exception("fingerprint format unexpected");

// 3. Detached hybrid signature: verify, and reject a tampered payload.
using var signer = PqSigningKeyPair.Generate();
byte[] signature = await new PqSigner().SignAsync(new MemoryStream(secret), signer.PrivateKey);
await new PqVerifier().VerifyAsync(new MemoryStream(secret), signature, signer.PublicKey);
bool rejected = false;
try
{
    byte[] tampered = (byte[])secret.Clone();
    tampered[0] ^= 0x01;
    await new PqVerifier().VerifyAsync(new MemoryStream(tampered), signature, signer.PublicKey);
}
catch (PqSignatureException) { rejected = true; }
if (!rejected) throw new Exception("tampered content passed verification");

// 4. DI package resolves working, limit-carrying services.
var provider = new ServiceCollection()
    .AddPqFileEncryption(options, PqDecryptionLimits.Untrusted)
    .BuildServiceProvider();
byte[] viaDi = await provider.GetRequiredService<PqFileDecryptor>()
    .DecryptBytesAsync(await provider.GetRequiredService<PqFileEncryptor>().EncryptBytesAsync(secret, Passphrase), Passphrase);
if (!viaDi.AsSpan().SequenceEqual(secret)) throw new Exception("DI round trip failed");

Console.WriteLine($"CONSUMER-OK {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
EOF

echo "==> Building the consumer from packed artifacts (both target frameworks)"
BUILD_LOG="$WORK/consumer-build.log"
dotnet build -c Release --nologo > "$BUILD_LOG" 2>&1 || { cat "$BUILD_LOG"; exit 1; }
if ! grep -q "PQFE101" "$BUILD_LOG"; then
  echo "FAIL: the packed analyzer did not flag the literal passphrase (PQFE101 missing)" >&2
  cat "$BUILD_LOG"
  exit 1
fi
echo "    packed analyzer loaded and fired (PQFE101)"

for tfm in net8.0 net10.0; do
  echo "==> Running the consumer journey on $tfm"
  dotnet run -c Release -f "$tfm" --no-build | tail -1
done

# The packed tool's apphost resolves the runtime via DOTNET_ROOT when the SDK lives outside
# the default location (setup-dotnet exports it in CI; a user-dir install locally may not).
if [ -z "${DOTNET_ROOT:-}" ]; then
  DOTNET_BIN="$(perl -MCwd=realpath -e 'print realpath($ARGV[0])' "$(command -v dotnet)")"
  export DOTNET_ROOT="$(dirname "$DOTNET_BIN")"
fi

echo "==> Installing the packed pqfe tool from the feed"
TOOLS="$WORK/tools"
dotnet tool install --tool-path "$TOOLS" --add-source "$FEED" --configfile nuget.config \
  PostQuantum.FileEncryption.Tool --version "$LOCALVER" > /dev/null
PQFE="$TOOLS/pqfe"

echo "==> Driving the packed tool end to end"
TDIR="$WORK/tooltest"
mkdir -p "$TDIR"
cd "$TDIR"
export PQFE_PASS='packed-consumer tool passphrase'
echo "tool journey payload" > plain.txt

"$PQFE" encrypt plain.txt plain.pqfe --passphrase-env PQFE_PASS 2>/dev/null
"$PQFE" decrypt plain.pqfe plain.out --untrusted --passphrase-env PQFE_PASS 2>/dev/null
cmp -s plain.txt plain.out || { echo "FAIL: tool passphrase round trip"; exit 1; }

set +e
PQFE_PASS='the wrong passphrase' "$PQFE" decrypt plain.pqfe wrong.out --passphrase-env PQFE_PASS 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 65 ] && [ ! -e wrong.out ] || { echo "FAIL: wrong passphrase should exit 65 with no output (got $rc)"; exit 1; }

"$PQFE" recipient keygen id.key --encrypt --passphrase-env PQFE_PASS 2>/dev/null
"$PQFE" recipient encrypt plain.txt sealed.pqfe --recipient id.key.pub 2>/dev/null
"$PQFE" recipient decrypt sealed.pqfe sealed.out --identity id.key --untrusted --passphrase-env PQFE_PASS 2>/dev/null
cmp -s plain.txt sealed.out || { echo "FAIL: tool recipient round trip"; exit 1; }
FP="$("$PQFE" recipient fingerprint id.key.pub 2>/dev/null)"
case "$FP" in pqfp1:*) ;; *) echo "FAIL: fingerprint output '$FP'"; exit 1 ;; esac

"$PQFE" keygen sign.key --encrypt --passphrase-env PQFE_PASS 2>/dev/null
"$PQFE" sign plain.txt sign.key --passphrase-env PQFE_PASS 2>/dev/null
"$PQFE" verify plain.txt sign.key.pub 2>/dev/null
set +e
printf 'tampered' >> plain.txt
"$PQFE" verify plain.txt sign.key.pub 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 65 ] || { echo "FAIL: tampered verify should exit 65 (got $rc)"; exit 1; }

echo "==> PASS — all nine packed packages verified as consumers receive them ($VERSION)"
