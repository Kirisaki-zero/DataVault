using System.Security.Cryptography;

namespace DataVault.Core.Encryption;

/// <summary>
/// AES-256-CBC engine. Memanfaatkan akselerasi hardware ARM64
/// melalui AesManaged → pada runtime Android ARM64 diarahkan
/// ke instruksi AES native (AES-NI / ARMv8 Crypto Extension).
/// </summary>
public sealed class AesCbcEngine : IDisposable
{
    // Ukuran buffer 80 KB: optimal untuk cache L2 perangkat ARM mid-range
    private const int BufferSize = 81_920;

    private readonly byte[] _key; // 32 byte = AES-256

    public AesCbcEngine(byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Kunci harus 32 byte (AES-256).");
        _key = key;
    }

    /// <summary>
    /// Enkripsi file byte-per-byte dengan streaming.
    /// Mengembalikan IV yang digunakan — simpan di database.
    /// </summary>
    public async Task<(string vaultPath, byte[] iv, string sha256Hash)>
        EncryptFileAsync(
            string sourcePath,
            string vaultDirectory,
            CancellationToken ct = default)
    {
        // Generate IV acak 16 byte
        byte[] iv = RandomNumberGenerator.GetBytes(16);

        // Nama file acak + ekstensi kustom
        string vaultName = $"{Guid.NewGuid():N}.dvx";
        string vaultPath = Path.Combine(vaultDirectory, vaultName);

        using var aes = Aes.Create();
        aes.KeySize  = 256;
        aes.Mode     = CipherMode.CBC;
        aes.Padding  = PaddingMode.PKCS7;
        aes.Key      = _key;
        aes.IV       = iv;

        // Hitung hash dari output terenkripsi sekaligus menulis
        using var sha256 = SHA256.Create();

        await using var sourceStream = new FileStream(
            sourcePath, FileMode.Open, FileAccess.Read,
            FileShare.None, BufferSize, useAsync: true);

        await using var vaultStream = new FileStream(
            vaultPath, FileMode.Create, FileAccess.Write,
            FileShare.None, BufferSize, useAsync: true);

        // Tulis IV di awal file vault (diperlukan saat dekripsi)
        await vaultStream.WriteAsync(iv, ct);

        using var cryptoStream = new CryptoStream(
            vaultStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

        var buffer = new byte[BufferSize];
        int bytesRead;

        while ((bytesRead = await sourceStream.ReadAsync(buffer, ct)) > 0)
        {
            await cryptoStream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);
        }

        await cryptoStream.FlushFinalBlockAsync(ct);

        // Flush sebelum hash agar data lengkap
        await vaultStream.FlushAsync(ct);

        // Hitung SHA-256 dari file vault yang sudah jadi
        string sha256Hash = await ComputeFileHashAsync(vaultPath, ct);

        return (vaultPath, iv, sha256Hash);
    }

    /// <summary>
    /// Dekripsi file vault ke lokasi tujuan.
    /// </summary>
    public async Task DecryptFileAsync(
        string vaultPath,
        string outputPath,
        CancellationToken ct = default)
    {
        await using var vaultStream = new FileStream(
            vaultPath, FileMode.Open, FileAccess.Read,
            FileShare.None, BufferSize, useAsync: true);

        // Baca IV dari 16 byte pertama file
        byte[] iv = new byte[16];
        _ = await vaultStream.ReadAsync(iv, ct);

        using var aes = Aes.Create();
        aes.KeySize  = 256;
        aes.Mode     = CipherMode.CBC;
        aes.Padding  = PaddingMode.PKCS7;
        aes.Key      = _key;
        aes.IV       = iv;

        await using var outputStream = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, BufferSize, useAsync: true);

        using var cryptoStream = new CryptoStream(
            vaultStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

        await cryptoStream.CopyToAsync(outputStream, BufferSize, ct);
    }

    /// <summary>
    /// SHA-256 streaming: tidak muat seluruh file ke RAM.
    /// </summary>
    public static async Task<string> ComputeFileHashAsync(
        string filePath,
        CancellationToken ct = default)
    {
        using var sha256 = SHA256.Create();
        await using var stream = new FileStream(
            filePath, FileMode.Open, FileAccess.Read,
            FileShare.None, BufferSize, useAsync: true);

        byte[] hashBytes = await sha256.ComputeHashAsync(stream, ct);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public void Dispose()
    {
        // Hapus kunci dari memori secara eksplisit
        CryptographicOperations.ZeroMemory(_key);
    }
}