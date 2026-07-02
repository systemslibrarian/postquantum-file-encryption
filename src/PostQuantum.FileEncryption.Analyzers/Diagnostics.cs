using Microsoft.CodeAnalysis;

namespace PostQuantum.FileEncryption.Analyzers;

/// <summary>
/// The diagnostic descriptors for the <c>PQFE1xx</c> misuse rules. The <c>PQFE0xx</c> range is
/// reserved for the library's own <see cref="System.ObsoleteAttribute"/> ids (e.g.
/// <c>PQFE002</c>), so analyzer rules start at 101. Each rule mirrors an entry in
/// docs/ANTI-PATTERNS.md, which is the long-form explanation the help link points at.
/// </summary>
internal static class Diagnostics
{
    private const string Category = "Security";
    private const string AntiPatternsUrl =
        "https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ANTI-PATTERNS.md";

    public static readonly DiagnosticDescriptor HardcodedPassphrase = new(
        id: "PQFE101",
        title: "Passphrase is a compile-time constant",
        messageFormat: "The passphrase is a compile-time constant; anyone with the source or binary can decrypt this data",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "A passphrase embedded in source code ships with every copy of the assembly and "
            + "survives in source control forever, so the encryption protects nothing against anyone "
            + "who can obtain the code or binary. Read the passphrase from a secret store, an "
            + "environment variable scoped to the process, or an interactive prompt instead.",
        helpLinkUri: AntiPatternsUrl + "#pqfe101");

    public static readonly DiagnosticDescriptor RawPrivateKeyToDisk = new(
        id: "PQFE102",
        title: "Raw private-key bytes written to disk",
        messageFormat: "Raw private-key bytes from Export() are written to disk; prefer ExportEncrypted, which produces a passphrase-protected, tamper-evident key file",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Export() returns the unprotected secret key. Written to disk, it is readable by "
            + "anything that can read the file, forever. ExportEncrypted wraps the same key in an "
            + "authenticated, Argon2id-hardened key file (the PQKF format) that fails closed on a "
            + "wrong passphrase or any tampering.",
        helpLinkUri: AntiPatternsUrl + "#pqfe102");

    public static readonly DiagnosticDescriptor UnawaitedCryptoOperation = new(
        id: "PQFE103",
        title: "Encrypt/decrypt/sign/verify task is discarded",
        messageFormat: "The task returned by '{0}' is discarded; the operation may not have completed and its failure — including an authentication failure — is never observed",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "These operations complete asynchronously, and their exceptions are the fail-closed "
            + "signal that data is inauthentic or a write did not finish. Discarding the task means "
            + "code continues as if the operation succeeded. Await the task (or explicitly assign it "
            + "and observe it later).",
        helpLinkUri: AntiPatternsUrl + "#pqfe103");

    public static readonly DiagnosticDescriptor SwallowedFailClosedException = new(
        id: "PQFE104",
        title: "Fail-closed exception is silently swallowed",
        messageFormat: "'{0}' is caught and silently discarded; this is the library's signal that data is inauthentic, forged, or corrupt — handle it or let it propagate",
        category: Category,
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "PqDecryptionException and PqSignatureException mean authentication failed: a wrong "
            + "key, altered bytes, or a forged signature. An empty catch block turns that hard stop "
            + "into silent success for whatever code runs next. Log it, surface it to the caller, or "
            + "abort the operation — never continue as if nothing happened. Catching the structural "
            + "PqFormatException to probe whether bytes are a container is fine and is not flagged.",
        helpLinkUri: AntiPatternsUrl + "#pqfe104");

    /// <summary>The library's root namespace — the marker for "this call is ours to judge".</summary>
    public static bool IsPqfeSymbol(ISymbol? symbol)
    {
        for (INamespaceSymbol? ns = symbol?.ContainingNamespace; ns is not null; ns = ns.ContainingNamespace)
        {
            if (ns.Name == "FileEncryption" && ns.ContainingNamespace?.Name == "PostQuantum")
            {
                return true;
            }
        }
        return false;
    }
}
