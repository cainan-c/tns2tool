# Taiko no Tatsujin: Rhythm Festival (PC/XBOX/PS5) File Decryption and Encryption Tool

Simple CLI program designed to decrypt and re-encrypt files for the "next-gen" ports of Taiko no Tatsujin: Rhythm Festival.  
Credit to [TraceEntertains](https://github.com/TraceEntertains) for his work on decompiling and figuring out how this game handles encryption, along with writing the cryptography code this project relies on.  

```
Usage:
  tns2tool.exe -e -inFile {file} [-gzip]   -> Encrypt the file (optionally compress with GZIP)
  tns2tool.exe -d -inFile {file} [-gzip]   -> Decrypt the file (optionally decompress with GZIP)
  tns2tool.exe -e -inPath {folder} [-gzip] -> Encrypt all files in the folder (optionally compress with GZIP)
  tns2tool.exe -d -inPath {folder} [-gzip] -> Decrypt all files in the folder (optionally decompress with GZIP)
```
