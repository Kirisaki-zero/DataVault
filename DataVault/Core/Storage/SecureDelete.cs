namespace DataVault.Core.Storage;

/// <summary>
/// Penghapusan file dengan overwrite sebelum delete.
/// Catatan: pada flash storage (eMMC/UFS), overwrite tidak 100%
/// menjamin penghapusan fisik karena wear-leveling. Ini adalah
/// lapisan terbaik yang bisa dilakukan di level aplikasi.
/// </summary>
public static class SecureDelete
{
    private const int OverwritePasses = 3;
    private const int BufferSize      = 65_536;

    public static async Task DeleteAsync(
        string filePath,
        CancellationToken ct = default)
    {
        if (!File.Exists(filePath)) return;

        var fileInfo = new FileInfo(filePath);
        long fileSize = fileInfo.Length;

        await using var stream = new FileStream(
            filePath, FileMode.Open, FileAccess.Write,
            FileShare.None, BufferSize, useAsync: true);

        // Pass 1: tulis semua 0x00
        // Pass 2: tulis semua 0xFF
        // Pass 3: tulis data acak
        byte[][] patterns =
        [
            new byte[BufferSize],                              // semua 0
            Enumerable.Repeat((byte)0xFF, BufferSize).ToArray(), // semua 255
            null!                                              // acak
        ];

        for (int pass = 0; pass < OverwritePasses; pass++)
        {
            stream.Seek(0, SeekOrigin.Begin);
            long remaining = fileSize;
            var  buffer    = patterns[pass];

            while (remaining > 0)
            {
                int chunkSize = (int)Math.Min(BufferSize, remaining);

                if (pass == 2) // Pass acak
                {
                    buffer = new byte[chunkSize];
                    Random.Shared.NextBytes(buffer);
                }

                await stream.WriteAsync(
                    buffer.AsMemory(0, chunkSize), ct);

                remaining -= chunkSize;
            }

            await stream.FlushAsync(ct);
        }

        stream.Close();
        File.Delete(filePath);
    }
}