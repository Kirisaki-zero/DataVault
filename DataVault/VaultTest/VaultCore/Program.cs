using System.Security.Cryptography;
using System.Text;

// ── SETUP DIREKTORI ──────────────────────────────────────
string baseDir   = Path.Combine(AppContext.BaseDirectory, "vault_test");
string vaultDir  = Path.Combine(baseDir, "vault");
string outputDir = Path.Combine(baseDir, "restored");

Directory.CreateDirectory(vaultDir);
Directory.CreateDirectory(outputDir);

// ── MENU UTAMA ───────────────────────────────────────────
while (true)
{
    Console.WriteLine("\n========================================");
    Console.WriteLine("  DataVault - Encryption Core Test");
    Console.WriteLine("========================================");
    Console.WriteLine("  [1] Enkripsi file");
    Console.WriteLine("  [2] Dekripsi file .dvx");
    Console.WriteLine("  [3] Lihat isi folder vault");
    Console.WriteLine("  [0] Keluar");
    Console.WriteLine("========================================");
    Console.Write("Pilih menu: ");

    string? choice = Console.ReadLine()?.Trim();
    Console.WriteLine();

    switch (choice)
    {
        case "1": await MenuEnkripsi(); break;
        case "2": await MenuDekripsi(); break;
        case "3": MenuLihatVault();     break;
        case "0":
            Console.WriteLine("Keluar.");
            return;
        default:
            Console.WriteLine("[!] Pilihan tidak valid.");
            break;
    }
}

// ════════════════════════════════════════════════════════
//  MENU 1: ENKRIPSI
// ════════════════════════════════════════════════════════
async Task MenuEnkripsi()
{
    string filePath = TanyaPathFile("Masukkan path file yang ingin dienkripsi");
    if (filePath == "") return;

    string pin = TanyaPin("Buat PIN angka untuk enkripsi");
    if (pin == "") return;

    Console.WriteLine();

    var    info     = new FileInfo(filePath);
    string fileName = info.Name;
    string fileExt  = info.Extension.ToUpperInvariant();
    long   fileSize = info.Length;

    Console.WriteLine($"[+] File             : {fileName}");
    Console.WriteLine($"[+] Tipe             : {(string.IsNullOrEmpty(fileExt) ? "tidak diketahui" : fileExt)}");
    Console.WriteLine($"[+] Ukuran           : {FormatSize(fileSize)}");

    Console.Write("\n[?] Hapus file asli setelah enkripsi? (y/n): ");
    bool hapusAsli = Console.ReadLine()?.Trim().ToLower() == "y";

    Console.WriteLine("\n--- KEY DERIVATION ---");
    byte[] salt  = KeyDerivation.GenerateSalt();
    byte[] key   = KeyDerivation.DeriveKey(pin, salt);
    Console.WriteLine($"[+] Salt (hex)       : {ToHex(salt)}");
    Console.WriteLine($"[PENTING] Catat salt ini untuk dekripsi nanti!");
    Console.WriteLine($"[+] Kunci AES-256    : {ToHex(key)[..32]}...");

    Console.WriteLine("\n--- ENKRIPSI AES-256-CBC ---");
    var engine = new AesCbcEngine(key);

    try
    {
        var (vaultPath, iv, hash) = await engine.EncryptFileAsync(filePath, vaultDir);

        Console.WriteLine($"[+] File vault       : {Path.GetFileName(vaultPath)}");
        Console.WriteLine($"[+] IV (hex)         : {ToHex(iv)}");
        Console.WriteLine($"[+] SHA-256          : {hash}");
        Console.WriteLine($"[+] Ukuran vault     : {FormatSize(new FileInfo(vaultPath).Length)}");

        string hashVerify = await AesCbcEngine.ComputeFileHashAsync(vaultPath);
        bool   valid      = hash == hashVerify;
        Console.WriteLine($"[+] Integritas       : {(valid ? "VALID" : "GAGAL")}");

        Console.WriteLine("\n--- RECORD DATABASE ---");
        Console.WriteLine($"[+] ID               : {Guid.NewGuid()}");
        Console.WriteLine($"[+] Nama asli        : {fileName}");
        Console.WriteLine($"[+] Nama vault       : {Path.GetFileName(vaultPath)}");
        Console.WriteLine($"[+] IV (base64)      : {Convert.ToBase64String(iv)}");
        Console.WriteLine($"[+] Salt (base64)    : {Convert.ToBase64String(salt)}");
        Console.WriteLine($"[+] Waktu            : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        if (hapusAsli)
        {
            Console.WriteLine("\n--- SECURE DELETE ---");
            await SecureDelete.DeleteAsync(filePath);
            bool deleted = !File.Exists(filePath);
            Console.WriteLine($"[+] File asli dihapus: {(deleted ? "BERHASIL" : "GAGAL")}");
        }

        Console.WriteLine($"\n[OK] File vault tersimpan di:\n     {vaultPath}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[!] Error enkripsi: {ex.Message}");
    }
    finally
    {
        engine.Dispose();
        CryptographicOperations.ZeroMemory(key);
    }
}

// ════════════════════════════════════════════════════════
//  MENU 2: DEKRIPSI
// ════════════════════════════════════════════════════════
async Task MenuDekripsi()
{
    var dvxFiles = Directory.GetFiles(vaultDir, "*.dvx");
    if (dvxFiles.Length == 0)
    {
        Console.WriteLine("[!] Folder vault kosong. Enkripsi file dulu.");
        return;
    }

    Console.WriteLine("File .dvx tersedia di vault:");
    for (int i = 0; i < dvxFiles.Length; i++)
        Console.WriteLine($"  [{i + 1}] {Path.GetFileName(dvxFiles[i])}");

    Console.Write("\nNomor file (atau ketik path manual): ");
    string? input = Console.ReadLine()?.Trim().Trim('"');

    string vaultFilePath;
    if (int.TryParse(input, out int nomor) && nomor >= 1 && nomor <= dvxFiles.Length)
        vaultFilePath = dvxFiles[nomor - 1];
    else if (File.Exists(input ?? ""))
        vaultFilePath = input!;
    else
    {
        Console.WriteLine("[!] File tidak ditemukan");
        return;
    }

    Console.Write("Nama file hasil dekripsi (contoh: foto.jpg): ");
    string? outName = Console.ReadLine()?.Trim();
    if (string.IsNullOrWhiteSpace(outName))
    {
        Console.WriteLine("[!] Nama file tidak boleh kosong.");
        return;
    }

    string pin = TanyaPin("Masukkan PIN enkripsi");
    if (pin == "") return;

    Console.Write("Masukkan Salt hex yang dicatat saat enkripsi: ");
    string? saltHex = Console.ReadLine()?.Trim();

    byte[] salt;
    try { salt = Convert.FromHexString(saltHex ?? ""); }
    catch { Console.WriteLine("[!] Format salt tidak valid."); return; }

    byte[] key    = KeyDerivation.DeriveKey(pin, salt);
    var    engine = new AesCbcEngine(key);
    string outPath = Path.Combine(outputDir, outName);

    Console.WriteLine("\n--- DEKRIPSI ---");
    try
    {
        await engine.DecryptFileAsync(vaultFilePath, outPath);
        Console.WriteLine($"[+] File dipulihkan  : {outPath}");
        Console.WriteLine($"[+] Ukuran           : {FormatSize(new FileInfo(outPath).Length)}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[!] Dekripsi gagal   : {ex.Message}");
        Console.WriteLine("    Kemungkinan PIN atau salt salah.");
    }
    finally
    {
        engine.Dispose();
        CryptographicOperations.ZeroMemory(key);
    }
}

// ════════════════════════════════════════════════════════
//  MENU 3: LIHAT VAULT
// ════════════════════════════════════════════════════════
void MenuLihatVault()
{
    var files = Directory.GetFiles(vaultDir, "*.dvx");
    Console.WriteLine($"Folder vault : {vaultDir}");
    Console.WriteLine($"Total file   : {files.Length}\n");

    if (files.Length == 0) { Console.WriteLine("(kosong)"); return; }

    foreach (var f in files)
    {
        var fi = new FileInfo(f);
        Console.WriteLine($"  {fi.Name}  |  {FormatSize(fi.Length)}  |  {fi.LastWriteTime:yyyy-MM-dd HH:mm}");
    }
}

// ════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════
static string TanyaPathFile(string prompt)
{
    while (true)
    {
        Console.Write($"{prompt}: ");
        string? input = Console.ReadLine()?.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(input)) { Console.WriteLine("[!] Path tidak boleh kosong."); continue; }
        if (!File.Exists(input)) { Console.WriteLine($"[!] File tidak ditemukan: {input}"); continue; }
        return input;
    }
}

static string TanyaPin(string prompt)
{
    while (true)
    {
        Console.Write($"{prompt} (angka saja, min 4 digit): ");
        string? pin = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(pin))  { Console.WriteLine("[!] PIN tidak boleh kosong."); continue; }
        if (!pin.All(char.IsDigit))          { Console.WriteLine("[!] PIN harus angka saja."); continue; }
        if (pin.Length < 4)                  { Console.WriteLine("[!] PIN minimal 4 digit."); continue; }
        return pin;
    }
}

static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

static string FormatSize(long bytes)
{
    if (bytes < 1024)        return $"{bytes} B";
    if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
    return $"{bytes / (1024.0 * 1024):F2} MB";
}


// ════════════════════════════════════════════════════════
//  CLASS: AesCbcEngine
// ════════════════════════════════════════════════════════
public sealed class AesCbcEngine : IDisposable
{
    private const int BufferSize = 81_920;
    private readonly byte[] _key;

    public AesCbcEngine(byte[] key)
    {
        if (key.Length != 32) throw new ArgumentException("Kunci harus 32 byte.");
        _key = (byte[])key.Clone();
    }

    public async Task<(string vaultPath, byte[] iv, string sha256Hash)>
        EncryptFileAsync(string sourcePath, string vaultDirectory, CancellationToken ct = default)
    {
        byte[] iv        = RandomNumberGenerator.GetBytes(16);
        string vaultName = $"{Guid.NewGuid():N}.dvx";
        string vaultPath = Path.Combine(vaultDirectory, vaultName);

        using var aes = Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7; aes.Key = _key; aes.IV = iv;

        await using var srcStream = new FileStream(sourcePath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);
        {
            await using var vaultStream = new FileStream(vaultPath, FileMode.Create,
                FileAccess.Write, FileShare.None, BufferSize, useAsync: true);
            await vaultStream.WriteAsync(iv, ct);
            using var cs = new CryptoStream(vaultStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            var buf = new byte[BufferSize]; int n;
            while ((n = await srcStream.ReadAsync(buf, ct)) > 0)
                await cs.WriteAsync(buf.AsMemory(0, n), ct);
            await cs.FlushFinalBlockAsync(ct);
            await vaultStream.FlushAsync(ct);
        }
        string hash = await ComputeFileHashAsync(vaultPath, ct);
        return (vaultPath, iv, hash);
    }

    public async Task DecryptFileAsync(string vaultPath, string outputPath, CancellationToken ct = default)
    {
        await using var vs = new FileStream(vaultPath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);
        byte[] iv = new byte[16];
        _ = await vs.ReadAsync(iv, ct);

        using var aes = Aes.Create();
        aes.KeySize = 256; aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7; aes.Key = _key; aes.IV = iv;

        await using var outStream = new FileStream(outputPath, FileMode.Create,
            FileAccess.Write, FileShare.None, BufferSize, useAsync: true);
        using var cs = new CryptoStream(vs, aes.CreateDecryptor(), CryptoStreamMode.Read);
        await cs.CopyToAsync(outStream, BufferSize, ct);
    }

    public static async Task<string> ComputeFileHashAsync(string filePath, CancellationToken ct = default)
    {
        using var sha = SHA256.Create();
        await using var s = new FileStream(filePath, FileMode.Open,
            FileAccess.Read, FileShare.None, BufferSize, useAsync: true);
        return Convert.ToHexString(await sha.ComputeHashAsync(s, ct)).ToLowerInvariant();
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

    public static byte[] GenerateSalt() => RandomNumberGenerator.GetBytes(SaltLength);

    public static byte[] DeriveKey(string pin, byte[] salt)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        return Rfc2898DeriveBytes.Pbkdf2(pinBytes, salt, Iterations, HashAlgorithmName.SHA256, KeyLength);
    }
}


// ════════════════════════════════════════════════════════
//  CLASS: SecureDelete
// ════════════════════════════════════════════════════════
public static class SecureDelete
{
    private const int Passes  = 3;
    private const int BufSize = 65_536;

    public static async Task DeleteAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath)) return;
        long fileSize = new FileInfo(filePath).Length;

        await using var stream = new FileStream(filePath, FileMode.Open,
            FileAccess.Write, FileShare.None, BufSize, useAsync: true);

        for (int pass = 0; pass < Passes; pass++)
        {
            stream.Seek(0, SeekOrigin.Begin);
            long rem = fileSize;
            while (rem > 0)
            {
                int chunk = (int)Math.Min(BufSize, rem);
                byte[] buf = new byte[chunk];
                if (pass == 0)      Array.Fill(buf, (byte)0x00);
                else if (pass == 1) Array.Fill(buf, (byte)0xFF);
                else                RandomNumberGenerator.Fill(buf);
                await stream.WriteAsync(buf.AsMemory(0, chunk), ct);
                rem -= chunk;
            }
            await stream.FlushAsync(ct);
        }
        stream.Close();
        File.Delete(filePath);
    }
}