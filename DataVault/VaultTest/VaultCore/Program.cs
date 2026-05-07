using System.Security.Cryptography;
using System.Text;

Console.WriteLine("========================================");
Console.WriteLine("  DataVault - Encryption Core Test");
Console.WriteLine("========================================\n");

// ── 1. SETUP ─────────────────────────────────────────────
string testDir   = Path.Combine(AppContext.BaseDirectory, "vault_test");
string vaultDir  = Path.Combine(testDir, "vault");
string outputDir = Path.Combine(testDir, "restored");

Directory.CreateDirectory(testDir);
Directory.CreateDirectory(vaultDir);
Directory.CreateDirectory(outputDir);

// Buat file dummy untuk dienkripsi
string originalPath = Path.Combine(testDir, "rahasia.txt");
string fileContent  = "Ini adalah data rahasia yang akan dienkripsi.\n" +
                      "Baris kedua berisi informasi sensitif.\n" +
                      "AES-256-CBC dengan akselerasi hardware ARM64/x64.";

await File.WriteAllTextAsync(originalPath, fileContent);
Console.WriteLine($"[+] File asli dibuat     : {originalPath}");
Console.WriteLine($"    Isi                  : {fileContent[..47]}...\n");

// ── 2. KEY DERIVATION (PBKDF2) ───────────────────────────
Console.WriteLine("--- KEY DERIVATION (PBKDF2-SHA256) ---");
string pin        = "123456";
byte[] salt       = KeyDerivation.GenerateSalt();
byte[] key        = KeyDerivation.DeriveKey(pin, salt);
byte[] dbKey      = KeyDerivation.DeriveKey(pin + ":db", salt); // kunci terpisah untuk DB

Console.WriteLine($"[+] PIN                  : {pin}");
Console.WriteLine($"[+] Salt (hex)           : {ToHex(salt)}");
Console.WriteLine($"[+] File Key (hex)       : {ToHex(key)}");
Console.WriteLine($"[+] DB Key (hex)         : {ToHex(dbKey)}");
Console.WriteLine($"[+] Iterasi PBKDF2       : 310.000\n");

// ── 3. ENKRIPSI FILE ─────────────────────────────────────
Console.WriteLine("--- ENKRIPSI FILE (AES-256-CBC) ---");
var engine = new AesCbcEngine(key);
var (vaultPath, iv, hashEncrypted) = await engine.EncryptFileAsync(originalPath, vaultDir);

Console.WriteLine($"[+] File vault           : {Path.GetFileName(vaultPath)}");
Console.WriteLine($"[+] IV (hex)             : {ToHex(iv)}");
Console.WriteLine($"[+] SHA-256 (terenkripsi): {hashEncrypted}");
Console.WriteLine($"[+] Ukuran vault         : {new FileInfo(vaultPath).Length} bytes\n");

// ── 4. VERIFIKASI INTEGRITAS ─────────────────────────────
Console.WriteLine("--- VERIFIKASI INTEGRITAS ---");
string hashVerify = await AesCbcEngine.ComputeFileHashAsync(vaultPath);
bool   valid      = hashEncrypted == hashVerify;
Console.WriteLine($"[+] Hash tersimpan       : {hashEncrypted}");
Console.WriteLine($"[+] Hash re-computed     : {hashVerify}");
Console.WriteLine($"[+] Integritas           : {(valid ? "VALID" : "RUSAK / TAMPERED")}\n");

// ── 5. CEK FILE TIDAK BISA DIBACA LANGSUNG ───────────────
Console.WriteLine("--- CEK KONTEN FILE VAULT ---");
byte[] rawBytes   = await File.ReadAllBytesAsync(vaultPath);
string rawPreview = Encoding.UTF8.GetString(rawBytes[16..Math.Min(80, rawBytes.Length)]);
Console.WriteLine($"[+] Preview raw bytes    : {ToHex(rawBytes[..16])}...");
Console.WriteLine($"[+] Baca sebagai teks    : {EscapeNonPrintable(rawPreview)}");
Console.WriteLine($"    (File manager/ekstraktor tidak bisa baca ini)\n");

// ── 6. SECURE DELETE FILE ASLI ───────────────────────────
Console.WriteLine("--- SECURE DELETE FILE ASLI ---");
await SecureDelete.DeleteAsync(originalPath);
bool deleted = !File.Exists(originalPath);
Console.WriteLine($"[+] File asli dihapus    : {(deleted ? "BERHASIL" : "GAGAL")}\n");

// ── 7. DEKRIPSI FILE ─────────────────────────────────────
Console.WriteLine("--- DEKRIPSI FILE ---");
string restoredPath = Path.Combine(outputDir, "rahasia_restored.txt");
await engine.DecryptFileAsync(vaultPath, restoredPath);

string restoredContent = await File.ReadAllTextAsync(restoredPath);
bool   contentMatch    = restoredContent == fileContent;

Console.WriteLine($"[+] File dipulihkan ke   : {restoredPath}");
Console.WriteLine($"[+] Konten cocok         : {(contentMatch ? "YA - DEKRIPSI BERHASIL" : "TIDAK - ADA KESALAHAN")}");
Console.WriteLine($"[+] Isi file pulih       : {restoredContent[..47]}...\n");

// ── 8. SIMULASI DATABASE RECORD ──────────────────────────
Console.WriteLine("--- SIMULASI DATABASE RECORD ---");
var record = new FileRecord
{
    Id            = Guid.NewGuid().ToString(),
    OriginalName  = "rahasia.txt",
    OriginalPath  = originalPath,
    VaultFileName = Path.GetFileName(vaultPath),
    Extension     = ".dvx",
    Sha256Hash    = hashEncrypted,
    FileSizeBytes = new FileInfo(vaultPath).Length,
    IvBase64      = Convert.ToBase64String(iv),
    SaltBase64    = Convert.ToBase64String(salt),
    EncryptedAt   = DateTime.UtcNow.ToString("o")
};

Console.WriteLine($"[+] ID                   : {record.Id}");
Console.WriteLine($"[+] Nama asli            : {record.OriginalName}");
Console.WriteLine($"[+] Path asli            : {record.OriginalPath}");
Console.WriteLine($"[+] Nama vault           : {record.VaultFileName}");
Console.WriteLine($"[+] Hash                 : {record.Sha256Hash[..32]}...");
Console.WriteLine($"[+] IV (base64)          : {record.IvBase64}");
Console.WriteLine($"[+] Salt (base64)        : {record.SaltBase64}");
Console.WriteLine($"[+] Waktu enkripsi       : {record.EncryptedAt}\n");

// ── 9. CLEANUP ───────────────────────────────────────────
engine.Dispose();
CryptographicOperations.ZeroMemory(key);
CryptographicOperations.ZeroMemory(dbKey);

Console.WriteLine("========================================");
Console.WriteLine("  SEMUA TEST BERHASIL");
Console.WriteLine("========================================");
Console.WriteLine($"\nFolder hasil test ada di:\n{testDir}");

// ── HELPER ───────────────────────────────────────────────
static string ToHex(byte[] bytes) =>
    Convert.ToHexString(bytes).ToLowerInvariant();

static string EscapeNonPrintable(string s) =>
    new string(s.Select(c => c < 32 || c > 126 ? '.' : c).ToArray());


// ════════════════════════════════════════════════════════
//  CLASS: AesCbcEngine
// ════════════════════════════════════════════════════════
public sealed class AesCbcEngine : IDisposable
{
    private const int BufferSize = 81_920;
    private readonly byte[] _key;

    public AesCbcEngine(byte[] key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Kunci harus 32 byte (AES-256).");
        _key = (byte[])key.Clone();
    }

    public async Task<(string vaultPath, byte[] iv, string sha256Hash)>
        EncryptFileAsync(string sourcePath, string vaultDirectory,
                         CancellationToken ct = default)
    {
        byte[] iv        = RandomNumberGenerator.GetBytes(16);
        string vaultName = $"{Guid.NewGuid():N}.dvx";
        string vaultPath = Path.Combine(vaultDirectory, vaultName);

        using var aes    = Aes.Create();
        aes.KeySize      = 256;
        aes.Mode         = CipherMode.CBC;
        aes.Padding      = PaddingMode.PKCS7;
        aes.Key          = _key;
        aes.IV           = iv;

        await using var srcStream = new FileStream(sourcePath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);

        // Blok using terpisah agar vaultStream tertutup sebelum hash dihitung
        {
            await using var vaultStream = new FileStream(vaultPath, FileMode.Create,
                FileAccess.Write, FileShare.None, BufferSize, useAsync: true);

            // Tulis IV 16 byte di kepala file
            await vaultStream.WriteAsync(iv, ct);

            using var cryptoStream = new CryptoStream(
                vaultStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

            var buffer = new byte[BufferSize];
            int bytesRead;
            while ((bytesRead = await srcStream.ReadAsync(buffer, ct)) > 0)
                await cryptoStream.WriteAsync(buffer.AsMemory(0, bytesRead), ct);

            await cryptoStream.FlushFinalBlockAsync(ct);
            await vaultStream.FlushAsync(ct);
        } // vaultStream ditutup di sini

        // Hitung hash setelah file sepenuhnya tertutup
        string hash = await ComputeFileHashAsync(vaultPath, ct);
        return (vaultPath, iv, hash);
    }

    public async Task DecryptFileAsync(string vaultPath, string outputPath,
                                       CancellationToken ct = default)
    {
        await using var vaultStream = new FileStream(vaultPath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);

        byte[] iv = new byte[16];
        _ = await vaultStream.ReadAsync(iv, ct);

        using var aes = Aes.Create();
        aes.KeySize   = 256;
        aes.Mode      = CipherMode.CBC;
        aes.Padding   = PaddingMode.PKCS7;
        aes.Key       = _key;
        aes.IV        = iv;

        await using var outStream = new FileStream(outputPath, FileMode.Create,
            FileAccess.Write, FileShare.None, BufferSize, useAsync: true);

        using var cryptoStream = new CryptoStream(
            vaultStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

        await cryptoStream.CopyToAsync(outStream, BufferSize, ct);
    }

    public static async Task<string> ComputeFileHashAsync(
        string filePath, CancellationToken ct = default)
    {
        using var sha256  = SHA256.Create();
        await using var s = new FileStream(filePath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);
        byte[] hash = await sha256.ComputeHashAsync(s, ct);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}


// ════════════════════════════════════════════════════════
//  CLASS: KeyDerivation
// ════════════════════════════════════════════════════════
public static class KeyDerivation
{
    private const int Iterations = 310_000;
    private const int KeyLength  = 32;
    private const int SaltLength = 16;

    public static byte[] GenerateSalt() =>
        RandomNumberGenerator.GetBytes(SaltLength);

    public static byte[] DeriveKey(string pin, byte[] salt)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        return Rfc2898DeriveBytes.Pbkdf2(
            pinBytes, salt, Iterations,
            HashAlgorithmName.SHA256, KeyLength);
    }
}


// ════════════════════════════════════════════════════════
//  CLASS: SecureDelete
// ════════════════════════════════════════════════════════
public static class SecureDelete
{
    private const int Passes    = 3;
    private const int BufSize   = 65_536;

    public static async Task DeleteAsync(string filePath,
                                         CancellationToken ct = default)
    {
        if (!File.Exists(filePath)) return;

        long fileSize = new FileInfo(filePath).Length;

        await using var stream = new FileStream(filePath, FileMode.Open,
            FileAccess.Write, FileShare.None, BufSize, useAsync: true);

        for (int pass = 0; pass < Passes; pass++)
        {
            stream.Seek(0, SeekOrigin.Begin);
            long remaining = fileSize;

            while (remaining > 0)
            {
                int   chunk  = (int)Math.Min(BufSize, remaining);
                byte[] buf   = new byte[chunk];

                if (pass == 0) Array.Fill(buf, (byte)0x00);
                else if (pass == 1) Array.Fill(buf, (byte)0xFF);
                else RandomNumberGenerator.Fill(buf);

                await stream.WriteAsync(buf.AsMemory(0, chunk), ct);
                remaining -= chunk;
            }

            await stream.FlushAsync(ct);
        }

        stream.Close();
        File.Delete(filePath);
    }
}


// ════════════════════════════════════════════════════════
//  MODEL: FileRecord
// ════════════════════════════════════════════════════════
public class FileRecord
{
    public string Id            { get; set; } = "";
    public string OriginalName  { get; set; } = "";
    public string OriginalPath  { get; set; } = "";
    public string VaultFileName { get; set; } = "";
    public string Extension     { get; set; } = ".dvx";
    public string Sha256Hash    { get; set; } = "";
    public long   FileSizeBytes { get; set; }
    public string IvBase64      { get; set; } = "";
    public string SaltBase64    { get; set; } = "";
    public string EncryptedAt   { get; set; } = "";
}