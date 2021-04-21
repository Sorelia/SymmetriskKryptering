using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace SymmetriskKryptering
{
    class TripleDes
    {
        /// <summary>
        /// Generates a random encrypted number
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] GenerateRandom(int length)
        {

            using (var generator = new RNGCryptoServiceProvider())
            {
                var number = new byte[length];
                generator.GetBytes(number);

                return number;
            }
        }

        public static byte[] Encrypt(string TextToEncrypt, byte[] key, byte[] iv)
        {
            byte[] text = Encoding.UTF8.GetBytes(TextToEncrypt);
            using (var tripleDES = new TripleDESCryptoServiceProvider())
            {
                tripleDES.Mode = CipherMode.CBC;
                tripleDES.Padding = PaddingMode.PKCS7;

                tripleDES.Key = key;
                tripleDES.IV = iv;

                using (var MemoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(MemoryStream, tripleDES.CreateEncryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(text, 0, text.Length);
                    cryptoStream.FlushFinalBlock();

                    return MemoryStream.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] TextToDecrypt, byte[] key, byte[] iv)
        {

            using (var tripleDES = new TripleDESCryptoServiceProvider())
            {
                tripleDES.Mode = CipherMode.CBC;
                tripleDES.Padding = PaddingMode.PKCS7;

                tripleDES.Key = key;
                tripleDES.IV = iv;

                using (var MemoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(MemoryStream, tripleDES.CreateDecryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(TextToDecrypt, 0, TextToDecrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    return MemoryStream.ToArray();
                }
            }
        }
    }
}
