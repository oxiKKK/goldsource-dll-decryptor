#ifndef BLOB_ALHORITHM
#define BLOB_ALHORITHM

#pragma once

#include <vector>

#define BLOB_ALGORITHM_MAGIC 0x12345678

struct blob_info_t
{
	char	m_szPath[10];
	char	m_szDescribe[32];
	char	m_szCompany[22];
	DWORD	m_dwMagic;				// Magic number that we use to identify whenether this file has been encrypted or not
};

struct blob_hdr_t
{
	DWORD	m_dwCheckSum;
	WORD	m_wSectionCount;
	DWORD	m_dwExportPoint;		// VA to some function, we don't care about that here
	DWORD	m_dwImageBase;			// Base virtual address of this image (0x1D00000)
	DWORD	m_dwEntryPoint;			// VA to entry point
	DWORD	m_dwImportTable;		// VA to import table
};

struct blob_section_t
{
	DWORD	m_dwVirtualAddress;		// VA from the image base
	DWORD	m_dwVirtualSize;		// The total size of the section when loaded into memory, in bytes. 
									// If this value is greater than the SizeOfRawData member, the section is filled with zeroes

	DWORD	m_dwDataSize;			// Raw data size of the section
	DWORD	m_dwDataAddress;		// RA from the base of encrypted buffer

	BOOL	m_bIsSpecial;			// Some valve thing to indicate whenether the section is special or not. Not important at all.
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
	blob_info_t*			m_info;
	blob_hdr_t*				m_header;
	blob_section_t*			m_sectionbase;
};

#endif