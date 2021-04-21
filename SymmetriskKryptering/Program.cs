using System;
using System.Text;

namespace SymmetriskKryptering
{
    class Program
    {
        static byte[] desKey = Des.GenerateRandom(8);
        static byte[] desIv = Des.GenerateRandom(8);

        static byte[] tdesKey = TripleDes.GenerateRandom(16);
        static byte[] tdesIv = TripleDes.GenerateRandom(8);

        static byte[] aesKey = AES.GenerateRandom(32);
        static byte[] aesIv = AES.GenerateRandom(16);

        static void Main(string[] args)
        {
            int i = 1;

            while (i == 1)
            {
                Console.WriteLine("Choose your encryptor: \r\n 1) AES, 2) Tripledes, 3) des");
                int choice = Convert.ToInt32(Console.ReadLine());
                string msg;
                switch (choice)
                {

                    case 1:
                        Console.WriteLine("Write your msg");
                        msg = Console.ReadLine();
                        byte[] aesEncrypttext = AES.Encrypt(msg, aesKey, aesIv);
                        msg = Convert.ToBase64String(aesEncrypttext);
                        Console.WriteLine("Encrypted message: " + msg);
                        byte[] aesdecryptedtext = AES.Decrypt(aesEncrypttext, aesKey, aesIv);
                        char[] aesdecryptedchars = Encoding.UTF8.GetChars(aesdecryptedtext);
                        msg = new string(aesdecryptedchars);
                        Console.WriteLine("Decrypted Message: " + msg);
                        break;
                    case 2:
                        Console.WriteLine("Write your msg");
                        msg = Console.ReadLine();
                        byte[] tdesEncrypttext = TripleDes.Encrypt(msg, tdesKey, tdesIv);
                        msg = Convert.ToBase64String(tdesEncrypttext);
                        Console.WriteLine("Encrypted message: " + msg);
                        byte[] tdesdecryptedtext = TripleDes.Decrypt(tdesEncrypttext, tdesKey, tdesIv);
                        char[] tdesdecryptedchars = Encoding.UTF8.GetChars(tdesdecryptedtext);
                        msg = new string(tdesdecryptedchars);
                        Console.WriteLine("Decrypted Message: " + msg);
                        break;
                    case 3:
                        Console.WriteLine("Write your msg");
                        msg = Console.ReadLine();
                        byte[] desencryptedtext = Des.Encrypt(msg, desKey, desIv);
                        msg = Convert.ToBase64String(desencryptedtext);
                        Console.WriteLine("Encrypted message: " + msg);
                        byte[] desdecryptedtext = Des.Decrypt(desencryptedtext, desKey, desIv);
                        char[] desdecryptedchars = Encoding.UTF8.GetChars(desdecryptedtext);
                        msg = new string(desdecryptedchars);
                        Console.WriteLine("Decrypted Message: " + msg);
                        break;
                }
            }
        }
    }
}
