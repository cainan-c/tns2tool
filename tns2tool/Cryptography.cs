// Credit goes to TraceEntertains (https://github.com/TraceEntertains) for creating this code.
using System.IO.Compression;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.IO.Enumeration;

namespace TNS2Crypto
{
    public static class Cryptography
    {
        // DonName (decoded)
        public static readonly string SeedBaseA = "VR32JhGV34nauGMLbNFHvPc5XqAkwjiB_";

        // KatsuName (decoded)
        public static readonly string SeedBaseB = "WQ3hcptFS4XkpugCn3fWA3qcPzSbY6fm_";

        // DonCount (decoded)
        public static readonly int KeyIterations = 7849;

        // KatsuCount (decoded)
        public static readonly int IVIterations = 5438;

        public static byte[] DecryptAllBytesAesAndGZip(string path)
        {
            byte[] byteBuffer = DecryptAllBytesAes(path, PaddingMode.Zeros);
            using MemoryStream dataStream = new(byteBuffer);
            using MemoryStream outStream = new();
            using GZipStream gzipStream = new(dataStream, CompressionMode.Decompress);

            gzipStream.CopyTo(outStream);
            // outStream.Position = 0 is not required due to the use of outStream.ToArray()

            // we can reuse the byteBuffer variable as the array is being overwritten entirely
            byteBuffer = outStream.ToArray();
            return byteBuffer;
        }

        public static byte[] DecryptAllBytesAes(string path, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] fileBuffer = File.ReadAllBytes(path);
            string fileName = Path.GetFileNameWithoutExtension(path);

            return DecryptAllBytesAes(fileBuffer, fileName, paddingMode);
        }

        public static byte[] DecryptAllBytesAes(byte[] encryptedBytes, string fileName, PaddingMode paddingMode)
        {
            using Aes aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = paddingMode;

            CreateKey(aes.KeySize, out byte[] keyOut, aes.BlockSize, out byte[] ivOut, fileName);

            aes.IV = ivOut;
            aes.Key = keyOut;

            using ICryptoTransform transform = aes.CreateDecryptor();
            using MemoryStream fileBufferStream = new(encryptedBytes, 0, encryptedBytes.Length);
            using CryptoStream decryptStream = new(fileBufferStream, transform, CryptoStreamMode.Read);
            using MemoryStream outStream = new();

            decryptStream.CopyTo(outStream);

            transform.Dispose();
            return outStream.ToArray();
        }

        public static byte[] EncryptAllBytesAesAndGZip(string path)
        {
            using FileStream fileStream = File.OpenRead(path);
            using GZipStream gzipStream = new(fileStream, CompressionMode.Compress);
            using MemoryStream outStream = new();

            gzipStream.CopyTo(outStream);
            gzipStream.Close();
            fileStream.Close();

            string fileName = Path.GetFileNameWithoutExtension(path);

            // outStream.Position = 0 is not required due to the use of outStream.ToArray()
            return EncryptAllBytesAes(outStream.ToArray(), fileName, PaddingMode.Zeros);
        }

        public static byte[] EncryptAllBytesAes(string filePath, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            byte[] fileBuffer = File.ReadAllBytes(filePath);
            string fileName = Path.GetFileNameWithoutExtension(filePath);

            return EncryptAllBytesAes(fileBuffer, fileName, paddingMode);
        }

        public static byte[] EncryptAllBytesAes(byte[] decryptedBytes, string fileName, PaddingMode paddingMode)
        {
            using Aes aes = Aes.Create();
            aes.BlockSize = 128;
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = paddingMode;

            CreateKey(aes.KeySize, out byte[] keyOut, aes.BlockSize, out byte[] ivOut, fileName);
            aes.Key = keyOut;
            aes.IV = ivOut;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            using MemoryStream encryptedStream = new();
            using CryptoStream cryptoStream = new(encryptedStream, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(decryptedBytes, 0, decryptedBytes.Length);
            cryptoStream.FlushFinalBlock();

            return encryptedStream.ToArray();
        }


        // thanks to Oman Computar for his input on the deobfuscation of the following 2 functions
        public static void CreateKey(int kSize, out byte[] keyOut, int bSize, out byte[] ivOut, string name)
        {
            byte[] seedABuffer = Encoding.UTF8.GetBytes(SeedBaseA + name);
            byte[] seedBBuffer = Encoding.UTF8.GetBytes(SeedBaseB + name);

            keyOut = CurryYomogi_Match(seedABuffer, seedBBuffer, KeyIterations, (int)((kSize >> 0x1f & 7U) + kSize) >> 3);
            ivOut = CurryYomogi_Match(seedABuffer, seedBBuffer, IVIterations, (int)((bSize >> 0x1f & 7U) + bSize) >> 3);
            return;
        }

        private static byte[] CurryYomogi_Match(byte[] seedA, byte[] seedB, int iterations, int outSize)
        {
            byte[] array;
            byte[] shiftArray = new byte[seedB.Length + 4];
            byte[] finalShiftArray;
            using MemoryStream memStream = new();

            using HMACSHA256 hS256 = new(seedA);
            int iVar2 = (int)((hS256.HashSize >> 0x1f & 7U) + hS256.HashSize) >> 3;
            
            int iVar9 = iVar2 + 1;
            if ((hS256.HashSize & 7) == 0)
            {
                iVar9 = iVar2;
            }
            
            try
            {
                if ((outSize <= iVar9 * 0xffffffff) && outSize > -1)
                {
                    iVar2 = outSize / iVar9 + 1;
                    if (outSize % iVar9 == 0)
                    {
                        iVar2 = outSize / iVar9;
                    }

                    Buffer.BlockCopy(seedB, 0, shiftArray, 0, seedB.Length);

                    int calcLoopIterator = 0;
                    while (calcLoopIterator < iVar2)
                    {
                        iVar9 = calcLoopIterator + 1;
                        
                        if (shiftArray.Length <= seedB.Length) return shiftArray;
                        shiftArray[seedB.Length] = (byte)((uint)iVar9 >> 24);
                        shiftArray[seedB.Length + 1] = (byte)((uint)iVar9 >> 16);
                        shiftArray[seedB.Length + 2] = (byte)((uint)iVar9 >> 8);
                        shiftArray[seedB.Length + 3] = (byte)(calcLoopIterator + 1);

                        array = hS256.ComputeHash(shiftArray);
                        Array.Clear(shiftArray, seedB.Length, 4);
                        finalShiftArray = array;

                        for (iVar9 = 1; iVar9 < iterations; iVar9++)
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
                    finalShiftArray = new byte[outSize];

                    memStream.Position = 0;
                    memStream.Read(finalShiftArray, 0, outSize);
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
