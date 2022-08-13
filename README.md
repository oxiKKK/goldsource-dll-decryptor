# GoldSource DLL decryptor for older builds

Some of the older engine builds (2003 - 2006) are encypted by Valve's blob modules encryption algorithm. This program is designed for decrypting these dlls to their original form.

# Usage

The program accepts one command-line argument as an input file. The output file will have same name with postfix **_dec.dll**.

```
gsdecrypt hw_3266.dll

Will output decrypted file "hw_3266_dec.dll" 
```

As example of encrypted file I've included the engine dll from build 3266 in the file list inside this repository.

# Why does this exist?

In order to open these DLLs in IDA, we have to decrypt them to their original PE-Image form. Otherwise IDA will recognize these encrypted files as pure binary files, rather than DLLs. This happens because of two things - These files are xored with magic number (the encryption) and they lack the entire PE header, which is esential for IDA when decompiling the file.

# Background information

Valve decided to encrypt their engine DLLs (hw & sw) from 2003 - 2006 era and then decided to stop, god knows why. Anyways, what they used is some kind of program that turns regular compiled DLLS into encrypted ones. 

## Encryption algorithm

The encryption algorithm does its work on the new DLL by storing only critical information in order for the loader (hl.exe) to load these files into memory, same as the windows PE loader does. This cricial information contains things such as VA (Virtual Address) of the entry point, IAT (Import Address Table), the image base address and more. 

The loader (hl.exe) takes the encrypted dll, locates it's entry point, copy its sections into memory, locates imports, and then calls the entry point. This is enough for the loader to load the engine dll into the memory, same as LoadLibrary would do, but in a custom way - with encrypted blob DLL.

Function inside the loader that is responsible for doing this is called **NLoadBlobFile()**.

### Pseudocode from the loader
```c++
//            filename    pblobfootprint         pv        not_used
NLoadBlobFile(enginedll, &g_blobfootprintClient, &pEngine, 0);
if (pEngine)
{
  // ...
  runResult = pEngine->vtbl->Run(pEngine, ...);
}

// This call to NLoadBlobFile() is absent in newer 
// versions of the game. Remains of this code can 
// still be found inside the 03 source leak.
```

# How to decrypt these encrypted files

There are some steps we have to do when we wan't to decrypt these encrypted files into their original form. Perhaps the most complicated is to actually fully reconstruct the entire PE header, which has quite some information in it. More information about Windows PE header can be found [here](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).

1) Read the blob header data from the ecrypted file (blob_info_t & blob_header_t)
2) Xor the entire encrypted buffer with letter W (That's the key that Valve used when ecrypting these DLLs)
3) Reconstruct original PE header (This includes the DOS header, Valve stub program, NT headers (Optional & File) and section data)
4) Reconstruct the Import address descriptor, IAT, Resources and Export data table.
5) Write reconstructed PE header into the new file and then write the section data.

# Difficulties

## PE header

When reconstructing the PE header, there are almost zero information available given from the original encrypted file. So the majority of the information stored inside PE header is just guessed or hardcoded by regular standards.

## Image sections

When reconstructing sections, there are no section names exposed via the blob header. We have to guess those. Usually, inside a DLL, the first section is the .text section, then the .rdata section and so on. Using this information, we can kind of guess, what sections are inside the encrypted file. But again, this is only a guess and may or may not work in other cases.

## Export address table (EAT)

While the blob header contains VA into the import table, there's no VA to the export table. We have to manually find it using some hacky hacks. The export table usually follows right after the import table (In these specific DLLs it's always like this), so we can get the export descriptor by just offseting to the last import table's thunk and go byte by byte until we find the export decriptor information. From there we can locate all the entries. Again, this is very DLL-specific, and works only in this case of these specific DLLs, but may or may not work for other DLLs as well.