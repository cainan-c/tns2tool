using System.IO.Compression;
using System.Text;
using System.Security.Cryptography;

namespace TNS2Crypto
{
    public static class Cryptography
    {
        public static readonly string KatsuName = "V1EzaGNwdEZTNFhrcHVnQ24zZldBM3FjUHpTYlk2Zm1f";
        public static readonly string DonName = "VlIzMkpoR1YzNG5hdUdNTGJORkh2UGM1WHFBa3dqaUJf";

        // don count is used in key
        public static readonly int DonCount = 0xffe156;

        // katsu count is used in iv
        public static readonly int KatsuCount = 0xfeac1;

        public static byte[] ReadAllAesAndGZipBytes(string path)
        {
            byte[] byteBuffer = ReadAllAesBytes(path);
            using MemoryStream dataStream = new(byteBuffer);
            using MemoryStream outStream = new();
            using GZipStream gzipStream = new(dataStream, CompressionMode.Decompress);

            gzipStream.CopyTo(outStream);
            // outStream.Position = 0 is not required due to the use of outStream.ToArray()

            // we can reuse the byteBuffer variable as the array is being overwritten entirely
            byteBuffer = outStream.ToArray();
            return byteBuffer;
        }

        public static byte[] ReadAllAesBytes(string path)
        {
            byte[] fileBuffer = File.ReadAllBytes(path);

            int count = fileBuffer.Length;
            byte[] outBuffer = new byte[count];

            using Aes aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;

            // I tried both PKCS7 | Zeros and PKCS7, PKCS7 | Zeros works but PKCS7 doesn't even though the game itself uses it lol
            aes.Padding = PaddingMode.Zeros;

            int kSize = aes.KeySize;
            int bSize = aes.BlockSize;

            string name = Path.GetFileNameWithoutExtension(path);

            CreateKey(kSize, out byte[] keyOut, bSize, out byte[] ivOut, name);

            aes.IV = ivOut;
            aes.Key = keyOut;

            using ICryptoTransform transform = aes.CreateDecryptor();
            using MemoryStream fileBufferStream = new(fileBuffer, 0, count);
            using CryptoStream decryptStream = new(fileBufferStream, transform, CryptoStreamMode.Read);
            using BinaryReader binaryReader = new(decryptStream);

            binaryReader.Read(outBuffer, 0, count);

            transform.Dispose();
            return outBuffer;
        }

        // this method is half broken and uses deprecated code
        //public static byte[] ReadAllAesBytes(string path)
        //{
        //    byte[] fileBuffer = File.ReadAllBytes(path);

        //    int count = fileBuffer.Length;
        //    byte[] outBuffer = new byte[count];

        //    using AesCryptoServiceProvider cryptoProvider = new()
        //    {
        //        BlockSize = 128,
        //        KeySize = 256,
        //        Mode = CipherMode.CBC,
        //        Padding = PaddingMode.PKCS7
        //    };

        //    int kSize = cryptoProvider.KeySize;
        //    int bSize = cryptoProvider.BlockSize;

        //    string name = Path.GetFileNameWithoutExtension(path);

        //    CreateKey(kSize, out byte[] keyOut, bSize, out byte[] ivOut, name);

        //    cryptoProvider.IV = ivOut;
        //    cryptoProvider.Key = keyOut;

        //    using ICryptoTransform transform = cryptoProvider.CreateDecryptor();
        //    using MemoryStream fileBufferStream = new(fileBuffer, 0, count);
        //    using CryptoStream decryptStream = new(fileBufferStream, transform, CryptoStreamMode.Read);
        //    using BinaryReader binaryReader = new(decryptStream);

        //    binaryReader.Read(outBuffer, 0, count);

        //    transform.Dispose();
        //    return outBuffer;
        //}

        public static void CreateKey(int kSize, out byte[] keyOut, int bSize, out byte[] ivOut, string name)
        {
            int donCount;
            int katsuCount;
            string donNameString;
            byte[] donNameBuffer;
            string katsuNameString;
            byte[] katsuNameBuffer;

            donNameBuffer = Convert.FromBase64String(DonName);
            donNameString = string.Concat(Encoding.UTF8.GetString(donNameBuffer), name);

            katsuNameBuffer = Convert.FromBase64String(KatsuName);
            katsuNameString = string.Concat(Encoding.UTF8.GetString(katsuNameBuffer), name);

            katsuCount = KatsuCount;
            donCount = DonCount;

            donNameBuffer = Encoding.UTF8.GetBytes(donNameString);
            katsuNameBuffer = Encoding.UTF8.GetBytes(katsuNameString);

            keyOut = CurryYomogi_Match(donNameBuffer, katsuNameBuffer, donCount ^ 0xffffff, (int)((kSize >> 0x1f & 7U) + kSize) >> 3);
            ivOut = CurryYomogi_Match(donNameBuffer, katsuNameBuffer, katsuCount ^ 0xfffff, (int)((bSize >> 0x1f & 7U) + bSize) >> 3);
            return;
        }

        private static byte[] CurryYomogi_Match(byte[] a, byte[] b, int c, int d)
        {
            byte[] array;
            byte[] shiftArray = new byte[b.Length + 4];
            byte[] finalShiftArray;
            using MemoryStream memStream = new();

            using HMACSHA256 hS256 = new(a);
            int iVar2 = (int)((hS256.HashSize >> 0x1f & 7U) + hS256.HashSize) >> 3;
            
            int iVar9 = iVar2 + 1;
            if ((hS256.HashSize & 7) == 0)
            {
                iVar9 = iVar2;
            }
            
            try
            {
                if ((d <= iVar9 * 0xffffffff) && d > -1)
                {
                    iVar2 = d / iVar9 + 1;
                    if (d % iVar9 == 0)
                    {
                        iVar2 = d / iVar9;
                    }

                    Buffer.BlockCopy(b, 0, shiftArray, 0, b.Length);

                    int calcLoopIterator = 0;
                    while (calcLoopIterator < iVar2)
                    {
                        iVar9 = calcLoopIterator + 1;
                        
                        if (shiftArray.Length <= b.Length) return shiftArray;
                        shiftArray[b.Length] = (byte)((uint)iVar9 >> 24);
                        shiftArray[b.Length + 1] = (byte)((uint)iVar9 >> 16);
                        shiftArray[b.Length + 2] = (byte)((uint)iVar9 >> 8);
                        shiftArray[b.Length + 3] = (byte)(calcLoopIterator + 1);

                        array = hS256.ComputeHash(shiftArray);
                        Array.Clear(shiftArray, b.Length, 4);
                        finalShiftArray = array;

                        for (iVar9 = 1; iVar9 < c; iVar9++)
                        {
                            finalShiftArray = hS256.ComputeHash(finalShiftArray);
                            int calcLoopIterator2 = 0;
                            while (true)
                            {
                                if (array.Length <= calcLoopIterator2) break;
                                array[calcLoopIterator2] ^= finalShiftArray[calcLoopIterator2];
                                calcLoopIterator2++;
                            }
                        }
                        memStream.Position = 0;
                        memStream.Write(array, 0, array.Length);

                        Array.Clear(finalShiftArray, 0, finalShiftArray.Length);
                        Array.Clear(array, 0, array.Length);
                        calcLoopIterator++;
                    }
                    finalShiftArray = new byte[d];
                    memStream.Position = 0;
                    memStream.Read(finalShiftArray, 0, d);
                    memStream.Position = 0;

                    memStream.Close();
                    Array.Clear(shiftArray, 0, shiftArray.Length);
                    return finalShiftArray;
                }
            } 
            catch (ArgumentOutOfRangeException ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }

            return shiftArray;
        }
    }
}
