using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SymmetriskKryptering
{
    class Des
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
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;

                des.Key = key;
                des.IV = iv;

                using (var MemoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(MemoryStream, des.CreateEncryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(text, 0, text.Length);
                    cryptoStream.FlushFinalBlock();

                    return MemoryStream.ToArray();
                }
            }
        }

        public static byte[] Decrypt(byte[] TextToDecrypt, byte[] key, byte[] iv)
        {
           
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;

                des.Key = key;
                des.IV = iv;

                using (var MemoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(MemoryStream, des.CreateDecryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(TextToDecrypt, 0, TextToDecrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    return MemoryStream.ToArray();
                }
            }
        }
    }
}
