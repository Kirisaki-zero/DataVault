using System.Security.Cryptography;
using System.Text;

namespace DataVault.Core.Encryption;

public static class KeyDerivation
{
    // PBKDF2 dengan 310.000 iterasi — rekomendasi OWASP 2024 untuk SHA-256
    private const int Iterations  = 310_000;
    private const int KeyLength   = 32; // 256 bit
    private const int SaltLength  = 16;

    /// <summary>
    /// Derivasi kunci AES dari PIN + salt.
    /// Salt baru di-generate saat pertama kali, simpan di database.
    /// </summary>
    public static (byte[] key, byte[] salt) DeriveNewKey(string pin)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] key  = DeriveKey(pin, salt);
        return (key, salt);
    }

    public static byte[] DeriveKey(string pin, byte[] salt)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);

        return Rfc2898DeriveBytes.Pbkdf2(
            pinBytes,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            KeyLength);
    }
}