using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace TNS2Tool
{
    public class Program
    {
        public static byte VersionMajor;
        public static byte VersionMinor;
        public static byte VersionRevision;
        public static string InformationalVersion;

        public static string GetFileVersion()
        {
            return $"{VersionMajor}.{VersionMinor}";
        }

        static void PopulateVersionInfo()
        {
            Version version = Assembly.GetEntryAssembly()!.GetName().Version!;
            VersionMajor = (byte)version.Major;
            VersionMinor = (byte)version.Minor;
            VersionRevision = (byte)version.Revision;

            InformationalVersion =
                FileVersionInfo.GetVersionInfo(Environment.ProcessPath!).ProductVersion!;
        }

        static void Main(string[] args)
        {
            // this is to work around restrictions in assemblyinfo
            PopulateVersionInfo();

            if (args.Length < 3)
            {
                Console.WriteLine($"Taiko no Tatsujin: Rhythm Festival (PC/XBOX/PS5) File Decryption and Encryption Tool (v{InformationalVersion})");
                Console.WriteLine("Special Thanks to TraceEntertains for the decryption/encryption logic used here");
                Console.WriteLine("");
                Console.WriteLine("Usage:");
                Console.WriteLine("  tns2tool.exe -e -inFile {file} [-gzip]   -> Encrypt the file (optionally compress with GZIP)");
                Console.WriteLine("  tns2tool.exe -d -inFile {file} [-gzip]   -> Decrypt the file (optionally decompress with GZIP)");
                Console.WriteLine("  tns2tool.exe -e -inPath {folder} [-gzip] -> Encrypt all files in the folder (optionally compress with GZIP)");
                Console.WriteLine("  tns2tool.exe -d -inPath {folder} [-gzip] -> Decrypt all files in the folder (optionally decompress with GZIP)");
                return;
            }

            string option = args[0];
            bool isGzip = Array.Exists(args, element => element == "-gzip");

            try
            {
                if (args[1] == "-inFile")
                {
                    string inputFile = args[2];
                    if (!File.Exists(inputFile))
                    {
                        Console.WriteLine("File not found: " + inputFile);
                        return;
                    }

                    ProcessFile(option, inputFile, isGzip, outputPath: null);
                }
                else if (args[1] == "-inPath")
                {
                    string inputPath = args[2];
                    if (!Directory.Exists(inputPath))
                    {
                        Console.WriteLine("Directory not found: " + inputPath);
                        return;
                    }

                    ProcessDirectory(option, inputPath, isGzip);
                }
                else
                {
                    Console.WriteLine("Unknown option. Use -inFile for single file or -inPath for directory.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        static void ProcessFile(string option, string inputFile, bool isGzip, string outputPath)
        {
            try
            {
                string outputFilePath;

                if (option == "-e")
                {
                    byte[] encryptedData;
                    if (isGzip)
                        encryptedData = Cryptography.EncryptAllBytesAesAndGZip(inputFile);
                    else
                        encryptedData = Cryptography.EncryptAllBytesAes(inputFile);
                    outputFilePath = GetOutputFileName(inputFile, outputPath, ".bin");
                    File.WriteAllBytes(outputFilePath, encryptedData);
                    Console.WriteLine("File encrypted: " + outputFilePath);
                }
                else if (option == "-d")
                {
                    byte[] decryptedData = isGzip ? Cryptography.DecryptAllBytesAesAndGZip(inputFile) : Cryptography.DecryptAllBytesAes(inputFile);
                    string fileExtension = DetermineFileExtension(decryptedData);
                    outputFilePath = GetOutputFileName(inputFile, outputPath, fileExtension);
                    File.WriteAllBytes(outputFilePath, decryptedData);
                    Console.WriteLine("File decrypted: " + outputFilePath);
                }
                else
                {
                    Console.WriteLine("Unknown option. Use -e for encryption or -d for decryption.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while processing file: " + ex.Message);
            }
        }

        static void ProcessDirectory(string option, string inputPath, bool isGzip)
        {
            string outputFolderName = option == "-e" ? $"{inputPath}_encrypted" : $"{inputPath}_decrypted";
            Directory.CreateDirectory(outputFolderName);

            string[] files = Directory.GetFiles(inputPath);

            foreach (string file in files)
            {
                Console.WriteLine($"Processing file: {file}");
                ProcessFile(option, file, isGzip, outputFolderName);
            }

            Console.WriteLine($"All files processed. Output folder: {outputFolderName}");
        }

        // Function to generate the output file name based on the input file and the output path
        static string GetOutputFileName(string inputFile, string outputPath, string newExtension)
        {
            string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(inputFile);
            string directory = outputPath ?? Path.GetDirectoryName(inputFile);

            return Path.Combine(directory, $"{fileNameWithoutExtension}{newExtension}");
        }

        // Function to determine the output file extension based on the content
        static string DetermineFileExtension(byte[] fileData)
        {
            if (fileData.Length >= 4)
            {
                // Check for .acb signature (40 55 54 46)
                if (fileData[0] == 0x40 && fileData[1] == 0x55 && fileData[2] == 0x54 && fileData[3] == 0x46)
                {
                    return ".acb";
                }

                // Check for .unity3d signature (55 6E 69 74 79 46 53)
                if (fileData.Length >= 7 && fileData[0] == 0x55 && fileData[1] == 0x6E && fileData[2] == 0x69 &&
                    fileData[3] == 0x74 && fileData[4] == 0x79 && fileData[5] == 0x46 && fileData[6] == 0x53)
                {
                    return ".unity3d";
                }

                // Check for GZIP signature (1F 8B)
                if (fileData[0] == 0x1F && fileData[1] == 0x8B)
                {
                    return ".gz";
                }
            }

            // Convert the byte array to a string for text-based file types
            string fileText = Encoding.UTF8.GetString(fileData);

            // Check if the file content is JSON (starts with '{' or '[' and ends with '}' or ']')
            if (fileText.TrimStart().StartsWith("{") && fileText.TrimEnd().EndsWith("}") ||
                fileText.TrimStart().StartsWith("[") && fileText.TrimEnd().EndsWith("]"))
            {
                return ".json";
            }

            // Refined CSV Detection: Check for a more consistent structure
            if (IsLikelyCsv(fileText))
            {
                return ".csv";
            }

            // Default extension if no specific format is detected (this generally handles fumen files)
            return Path.GetExtension(".dec.bin");
        }

        // Helper function to determine if the file content resembles a CSV file
        static bool IsLikelyCsv(string fileText)
        {
            // Split the text into lines
            string[] lines = fileText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            // Ensure there is more than one line (CSV typically has multiple rows)
            if (lines.Length < 2)
            {
                return false;
            }

            // Check the first few lines for consistent comma-separated values
            int columnCount = lines[0].Split(',').Length;

            // We expect at least some consistency in the number of columns for each row
            for (int i = 1; i < lines.Length && i < 10; i++)  // Check up to 10 lines for consistency
            {
                if (lines[i].Split(',').Length != columnCount)
                {
                    return false;
                }
            }

            // If the number of columns is consistent across rows, it's likely a CSV
            return true;
        }
    }
}
