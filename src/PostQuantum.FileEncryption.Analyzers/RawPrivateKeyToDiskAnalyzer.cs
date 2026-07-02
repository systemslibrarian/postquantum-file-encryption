using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.FileEncryption.Analyzers;

/// <summary>
/// PQFE102: flags <c>File.WriteAllBytes(path, key.Export())</c> (and the async variant) for a
/// PostQuantum.FileEncryption private-key type — the raw secret bytes are landing on disk when
/// <c>ExportEncrypted</c> exists precisely for that job. Only the direct-argument shape is
/// detected; the rule prefers missing a laundered copy over false-flagging unrelated writes.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class RawPrivateKeyToDiskAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(Diagnostics.RawPrivateKeyToDisk);

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (IInvocationOperation)context.Operation;
        IMethodSymbol method = invocation.TargetMethod;

        bool isFileWrite = method.Name is "WriteAllBytes" or "WriteAllBytesAsync"
            && method.ContainingType is { Name: "File", ContainingNamespace.Name: "IO" };
        if (!isFileWrite)
        {
            return;
        }

        foreach (IArgumentOperation argument in invocation.Arguments)
        {
            if (argument.Value is IInvocationOperation { TargetMethod: { Name: "Export" } export }
                && export.ContainingType?.Name.EndsWith("PrivateKey", System.StringComparison.Ordinal) == true
                && Diagnostics.IsPqfeSymbol(export))
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Diagnostics.RawPrivateKeyToDisk, invocation.Syntax.GetLocation()));
                return;
            }
        }
    }
}
