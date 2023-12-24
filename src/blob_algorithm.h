#ifndef BLOB_ALHORITHM
#define BLOB_ALHORITHM
#pragma once

#include <vector>

// classic signature that is used with engine and game modules
#define CLASSIC_BLOB_SIG 0x12345678

struct FakeCOFFHeader_t
{
	char rgchMisc[60]; 
	int dbSignature; 
	int nSignature; // Magic number that we use to identify whenether this file has been encrypted or not
};

struct BlobHeader_t
{
	int		nRandom;
	int	cblobunit;
	int	nAddressF;		// VA to some function, we don't care about that here
	int	nImageBase;		// Base virtual address of this image (0x1D00000)
	int	nEntryPoint;	// VA to entry point
	int	nImportDir;		// VA to import table
};

struct BlobUnit_t
{
	int		nAddress;	// VA from the image base
	int		cbMemSize;	// The total size of the section when loaded into memory, in bytes. 
						// If this value is greater than the SizeOfRawData member, the section is filled with zeroes

	int		cbFileSize;	// Raw data size of the section
	int		dbOffset;	// RA from the base of encrypted buffer

	char	fSpecial;	// Some valve thing to indicate whenether the section is special or not. Not important at all.
};

class blob_algorithm
{
public:
	static auto& get()
	{
		static blob_algorithm blob;
		return blob;
	}

public:
	bool decrypt_file_buffer(byte* filebuffer, uint32_t length);

	// Write raw data for each section into the file
	void write_section_data(byte* filebuffer, uint32_t file_alignment, std::ofstream& ofs);

private:
	// Checks for magic number
	bool valid_info_header();

	// Checks for blob header data
	bool valid_blob_data_header();

	// Xor the entire file using 'W'
	void xor_buffer(byte* filebuffer, uint32_t length);

private:
	FakeCOFFHeader_t*		m_fakecoff;
	BlobHeader_t*				m_header;
	BlobUnit_t*			m_sectionbase;
};

#endif