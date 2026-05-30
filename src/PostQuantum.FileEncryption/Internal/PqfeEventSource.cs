using System.Diagnostics.Tracing;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// Structured, opt-in telemetry for encrypt/decrypt operations, emitted via
/// <see cref="EventSource"/> (consumable by EventListener, dotnet-trace, EventPipe, and
/// OpenTelemetry, and pipeable into SIEMs). Events are <b>deliberately non-sensitive</b>:
/// operation kind, key-source/KDF label, byte counts, elapsed time, and failure category only —
/// <b>never</b> passphrases, keys, salts, nonces, or plaintext.
/// </summary>
[EventSource(Name = "PostQuantum.FileEncryption")]
internal sealed class PqfeEventSource : EventSource
{
    public static readonly PqfeEventSource Log = new();

    private PqfeEventSource() { }

    /// <summary>An encrypt or decrypt operation began.</summary>
    [Event(1, Level = EventLevel.Informational, Message = "{0} started (keySource={1})")]
    public void OperationStarted(string operation, string keySource)
    {
        if (IsEnabled())
        {
            WriteEvent(1, operation, keySource);
        }
    }

    /// <summary>An operation completed successfully.</summary>
    [Event(2, Level = EventLevel.Informational, Message = "{0} completed ({1} bytes in {2} ms)")]
    public void OperationCompleted(string operation, long bytesProcessed, double elapsedMilliseconds)
    {
        if (IsEnabled())
        {
            WriteEvent(2, operation, bytesProcessed, elapsedMilliseconds);
        }
    }

    /// <summary>An operation failed. <paramref name="reason"/> is an exception type name, not a message.</summary>
    [Event(3, Level = EventLevel.Warning, Message = "{0} failed ({1})")]
    public void OperationFailed(string operation, string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(3, operation, reason);
        }
    }
}
