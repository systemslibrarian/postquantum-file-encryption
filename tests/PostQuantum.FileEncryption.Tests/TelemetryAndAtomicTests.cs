using System.Diagnostics.Tracing;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Non-sensitive telemetry and the all-or-nothing stream decryption guarantee.</summary>
public sealed class TelemetryAndAtomicTests
{
    private sealed class CapturingListener : EventListener
    {
        public List<(string Name, string Op)> Events { get; } = new();

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name == "PostQuantum.FileEncryption")
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs e)
        {
            string op = e.Payload is { Count: > 0 } && e.Payload[0] is string s ? s : "";
            lock (Events) { Events.Add((e.EventName ?? "", op)); }
        }
    }

    [Fact]
    public async Task Encryption_emits_started_and_completed_telemetry()
    {
        using var listener = new CapturingListener();

        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(2000), Passphrase);
        _ = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);

        lock (listener.Events)
        {
            Assert.Contains(listener.Events, e => e is { Name: "OperationStarted", Op: "encrypt" });
            Assert.Contains(listener.Events, e => e is { Name: "OperationCompleted", Op: "encrypt" });
            Assert.Contains(listener.Events, e => e is { Name: "OperationStarted", Op: "decrypt" });
            Assert.Contains(listener.Events, e => e is { Name: "OperationCompleted", Op: "decrypt" });
        }
    }

    [Fact]
    public async Task Failed_decryption_emits_failure_telemetry()
    {
        using var listener = new CapturingListener();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), Passphrase);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "wrong"));

        lock (listener.Events)
        {
            Assert.Contains(listener.Events, e => e is { Name: "OperationFailed", Op: "decrypt" });
        }
    }

    [Fact]
    public async Task Atomic_decryption_writes_nothing_on_truncation()
    {
        byte[] original = RandomBytes(5000); // multiple 1 KiB chunks
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast(1024)).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        byte[] truncated = cipher.ToArray()[..1800]; // drop the tail

        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAtomicAsync(new MemoryStream(truncated), output, Passphrase));

        Assert.Equal(0, output.Length); // all-or-nothing: nothing emitted
    }

    [Fact]
    public async Task Atomic_decryption_round_trips_a_valid_container()
    {
        byte[] original = RandomBytes(5000);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast(1024)).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        cipher.Position = 0;

        using var output = new MemoryStream();
        await new PqFileDecryptor().DecryptAtomicAsync(cipher, output, Passphrase);
        Assert.Equal(original, output.ToArray());
    }
}
