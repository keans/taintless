using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Md = System.Security.Cryptography.MD5;

namespace Demo
{
    public class CryptoDemo
    {
        const string Algo = "MD5";
        static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789abcdef");

        public byte[] Hashes(byte[] data)
        {
            using var md5 = MD5.Create();
            var sha1 = new SHA1CryptoServiceProvider();
            var sha256 = SHA256.Create();
            var aliased = Md.Create();
            sha256.ComputeHash(data);
            md5.ComputeHash(data);
            return HashAlgorithm.Create(Algo).ComputeHash(data);
        }

        public byte[] Encrypt(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Key = Key;
            aes.IV = new byte[16];
            var des = DES.Create();
            using var rsa = new RSACryptoServiceProvider(1024);
            var kdf = new Rfc2898DeriveBytes("password", new byte[8], 1000);
            var hmac = new HMACSHA256(Encoding.UTF8.GetBytes("secret"));
            var rnd = new Random(42);
            var token = RandomNumberGenerator.GetBytes(16);
            return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }

        public void Tls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls12;
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
            var protocols = SslProtocols.Tls12 | SslProtocols.Tls13;
        }
    }
}
