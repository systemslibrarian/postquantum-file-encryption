using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.FileEncryption.Analyzers;

/// <summary>
/// PQFE103: flags a bare expression statement that discards the <c>Task</c> returned by a
/// PostQuantum.FileEncryption encrypt/decrypt/sign/verify call. Unlike the compiler's CS4014
/// (async methods only), this fires in synchronous contexts too — where the discarded task is
/// most often a genuine mistake. An explicit discard (<c>_ = ...</c>) is treated as the
/// developer taking responsibility and is not flagged.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class UnawaitedCryptoOperationAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(Diagnostics.UnawaitedCryptoOperation);

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeExpressionStatement, OperationKind.ExpressionStatement);
    }

    private static void AnalyzeExpressionStatement(OperationAnalysisContext context)
    {
        var statement = (IExpressionStatementOperation)context.Operation;
        if (statement.Operation is not IInvocationOperation invocation)
        {
            return;
        }

        IMethodSymbol method = invocation.TargetMethod;
        if (!Diagnostics.IsPqfeSymbol(method) || !IsCryptoOperationName(method.Name))
        {
            return;
        }

        bool returnsAwaitable = method.ReturnType is INamedTypeSymbol
        {
            Name: "Task" or "ValueTask",
            ContainingNamespace: { Name: "Tasks", ContainingNamespace.Name: "Threading" },
        };
        if (returnsAwaitable)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Diagnostics.UnawaitedCryptoOperation, statement.Syntax.GetLocation(), method.Name));
        }
    }

    private static bool IsCryptoOperationName(string name) =>
        name.StartsWith("Encrypt", System.StringComparison.Ordinal)
        || name.StartsWith("Decrypt", System.StringComparison.Ordinal)
        || name.StartsWith("Sign", System.StringComparison.Ordinal)
        || name.StartsWith("Verify", System.StringComparison.Ordinal);
}
