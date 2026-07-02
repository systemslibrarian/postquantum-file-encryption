; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
PQFE101 | Security | Warning | Passphrase is a compile-time constant
PQFE102 | Security | Warning | Raw private-key bytes written to disk
PQFE103 | Security | Warning | Encrypt/decrypt/sign/verify task is discarded
PQFE104 | Security | Warning | Fail-closed exception is silently swallowed
