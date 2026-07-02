using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.FileEncryption.Analyzers;

/// <summary>
/// PQFE104: flags an empty catch block for <c>PqDecryptionException</c>,
/// <c>PqSignatureException</c>, or their base <c>PqEncryptionException</c> — the library's
/// fail-closed signals. <c>PqFormatException</c> is deliberately exempt: catching it to probe
/// whether bytes are a container at all is a legitimate, key-free structural check.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SwallowedFailClosedExceptionAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(Diagnostics.SwallowedFailClosedException);

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeCatchClause, OperationKind.CatchClause);
    }

    private static void AnalyzeCatchClause(OperationAnalysisContext context)
    {
        var catchClause = (ICatchClauseOperation)context.Operation;

        string? typeName = catchClause.ExceptionType?.Name;
        bool isFailClosedSignal = typeName
            is "PqDecryptionException" or "PqSignatureException" or "PqEncryptionException";
        if (!isFailClosedSignal || !Diagnostics.IsPqfeSymbol(catchClause.ExceptionType))
        {
            return;
        }

        if (catchClause.Handler.Operations.IsEmpty)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Diagnostics.SwallowedFailClosedException,
                catchClause.Syntax.GetLocation(),
                typeName));
        }
    }
}
