namespace PostQuantum.FileEncryption.Gcp;

/// <summary>
/// CRC32C (Castagnoli) — the checksum Cloud KMS uses for its request/response integrity
/// fields. This is an error-detecting code, not a cryptographic primitive; authenticity is
/// carried by the AEAD layers on either side of it. Table-driven, reflected polynomial
/// <c>0x82F63B78</c>, matching RFC 3720 §B.4 and the values the service computes.
/// </summary>
internal static class Crc32C
{
    private static readonly uint[] Table = BuildTable();

    /// <summary>Computes the CRC32C of <paramref name="data"/>, widened to the service's <c>int64</c> field type.</summary>
    public static long Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFFu;
        foreach (byte b in data)
        {
            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }
        return ~crc;
    }

    private static uint[] BuildTable()
    {
        uint[] table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? 0x82F63B78u ^ (crc >> 1) : crc >> 1;
            }
            table[i] = crc;
        }
        return table;
    }
}
