#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "blob_algorithm.h"
#include "pe_builder.h"

bool blob_algorithm::decrypt_file_buffer(byte* filebuffer, uint32_t length)
{
	printf("Starting to decrypt the file...\n");

	m_info = reinterpret_cast<blob_info_t*>(filebuffer);

	printf("--- Blob info header ---\n");
	printf("  Path    : %s\n", m_info->m_szPath[0] != '\0' ? m_info->m_szPath : "none");
	printf("  Describe: %s\n", m_info->m_szDescribe[0] != '\0' ? m_info->m_szDescribe : "none");
	printf("  Company : %s\n", m_info->m_szCompany[0] != '\0' ? m_info->m_szCompany : "none");
	printf("  Magic   : 0x%08X\n", m_info->m_dwMagic);

	// Xor the entire file buffer with 'W'
	xor_buffer(filebuffer, length);

	// Get the blob header
	m_header = reinterpret_cast<blob_hdr_t*>(filebuffer + sizeof(blob_info_t));
	m_header->m_dwExportPoint ^= 0x7A32BC85;
	m_header->m_dwImageBase ^= 0x49C042D1;
	m_header->m_dwEntryPoint -= 0x0000000C;
	m_header->m_dwImportTable ^= 0x872C3D47;
	m_header->m_wSectionCount++; // In blob files, there's always one section+
	
	printf("--- Blob data header ---\n");
	printf("                %-10s %s\n", "VA", "RVA");
	printf("  Image base  : 0x%08X\n", m_header->m_dwImageBase);
	printf("  Entry point : 0x%08X 0x%08X\n", m_header->m_dwEntryPoint, m_header->m_dwEntryPoint - m_header->m_dwImageBase);
	printf("  Import table: 0x%08X 0x%08X\n", m_header->m_dwImportTable, m_header->m_dwImportTable - m_header->m_dwImageBase);
	printf("  Export      : 0x%08X 0x%08X\n", m_header->m_dwExportPoint, m_header->m_dwExportPoint - m_header->m_dwImageBase);
	printf("  Checksum    : 0x%08X\n", m_header->m_dwCheckSum);
	printf("  Sections    : %hu\n", m_header->m_wSectionCount);

	m_sectionbase = reinterpret_cast<blob_section_t*>(filebuffer + sizeof(blob_info_t) + sizeof(blob_hdr_t));

	if (!is_blob(length))
	{
		printf("Error: This isn't a valid blob file!\n");
		return false;
	}

	for (uint16_t i = 0; i < m_header->m_wSectionCount; i++)
	{
		blob_section_t* sec = &m_sectionbase[i];

		printf("--- Section %d ---\n", i);
		printf("  VA             : 0x%08X\n", sec->m_dwVirtualAddress);
		printf("  RVA            : 0x%08X\n", sec->m_dwVirtualAddress - m_header->m_dwImageBase);
		printf("  Virtual size   : %d bytes (0x%08X)\n", sec->m_dwVirtualSize, sec->m_dwVirtualSize);
		printf("  Data RA        : 0x%08X\n", sec->m_dwDataAddress);
		printf("  Data size      : %d bytes (0x%08X)\n", sec->m_dwDataSize, sec->m_dwDataSize);
		printf("  Is special     : %s\n", sec->m_bIsSpecial == TRUE ? "yes" : "no");
	}

	// Build pe header for the new image
	pe_builder::get().build_pe_header(filebuffer, m_header, m_sectionbase);

	return true;
}

bool blob_algorithm::is_blob(uint32_t length)
{
	if (length < sizeof(blob_info_t) + sizeof(blob_hdr_t))
	{
		printf("Error: Blob file has invalid length! (%d bytes)\n", length);
		return false;
	}

	if (!m_header->m_wSectionCount)
	{
		printf("Error: Blob has no sections! (%d)\n", m_header->m_wSectionCount);
		return false;
	}

	if (m_info->m_dwMagic != BLOB_ALGORITHM_MAGIC)
	{
		printf("Error: Invalid blob algorithm magic number: 0x%08X\n", m_info->m_dwMagic);
		return false;
	}

	return true;
}

void blob_algorithm::xor_buffer(byte* filebuffer, uint32_t length)
{
	uint8_t xor_char = 'W';

	// Start at blob_info header and continue xoring till the end
	for (uint32_t i = sizeof(blob_info_t); i < length; i++)
	{
		filebuffer[i] ^= xor_char;
		xor_char += filebuffer[i] + 'W';
	}
}

void blob_algorithm::write_section_data(byte* filebuffer, uint32_t file_alignment, std::ofstream& ofs)
{
	printf("[0x%08X] Writing section contents\n", (uint32_t)ofs.tellp());

	for (uint16_t i = 0; i < m_header->m_wSectionCount; i++)
	{
		auto sec = &m_sectionbase[i];

		ofs.write((const char*)&filebuffer[sec->m_dwDataAddress], sec->m_dwDataSize);

		printf("[0x%08X] Wrote %d bytes for section %d\n", (uint32_t)ofs.tellp(), sec->m_dwDataSize, i);

		// Sections are aligned to the FileAlignment value stored inside 
		// Optional Header.
		uint32_t mod = file_alignment - (sec->m_dwDataSize % file_alignment);

		if (mod != file_alignment)
		{
			byte* zero_buffer = new byte[file_alignment];
			memset(zero_buffer, NULL, file_alignment);

			ofs.write((const char*)zero_buffer, mod);

			printf("Section %d isn't 4096-aligned, had to write %d bytes of alignment.\n", i, mod);
			delete[] zero_buffer;
		}
	}
}
