using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.FileEncryption.Analyzers;

/// <summary>
/// PQFE101: flags a compile-time-constant string passed as the <c>passphrase</c> argument of
/// any PostQuantum.FileEncryption API. Matching on the parameter name rather than a method
/// list keeps the rule correct for every current and future passphrase-taking overload.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HardcodedPassphraseAnalyzer : DiagnosticAnalyzer
{
    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(Diagnostics.HardcodedPassphrase);

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
        if (!Diagnostics.IsPqfeSymbol(invocation.TargetMethod))
        {
            return;
        }

        foreach (IArgumentOperation argument in invocation.Arguments)
        {
            if (argument.Parameter?.Name != "passphrase")
            {
                continue;
            }

            // Unwrap conversions first: a string literal passed to a ReadOnlySpan<char>
            // parameter arrives wrapped in an implicit conversion operation.
            IOperation value = argument.Value;
            while (value is IConversionOperation conversion)
            {
                value = conversion.Operand;
            }

            // ConstantValue folds string literals, const locals, and const fields alike —
            // exactly the set of values that ship verbatim inside the assembly.
            if (value.ConstantValue is { HasValue: true, Value: string })
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Diagnostics.HardcodedPassphrase, argument.Syntax.GetLocation()));
            }
        }
    }
}
