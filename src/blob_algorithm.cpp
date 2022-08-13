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

	// Validate magic number
	if (!valid_info_header())
	{
		printf("Error: Bad blob info header!\n");
		return false;
	}

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

	// Validate addresses exposed by the blob header
	if (!valid_blob_data_header())
	{
		printf("Error: Bad blob data header!\n");
		return false;
	}

	// In blob files, there's always one section+, so we increment this now
	// so we don't have to do + 1 every time we use this afterwards.
	m_header->m_wSectionCount++;
	
	printf("--- Blob data header ---\n");
	printf("                %-10s %s\n", "VA", "RVA");
	printf("  Image base  : 0x%08X\n", m_header->m_dwImageBase);
	printf("  Entry point : 0x%08X 0x%08X\n", m_header->m_dwEntryPoint, m_header->m_dwEntryPoint - m_header->m_dwImageBase);
	printf("  Import table: 0x%08X 0x%08X\n", m_header->m_dwImportTable, m_header->m_dwImportTable - m_header->m_dwImageBase);
	printf("  Export      : 0x%08X 0x%08X\n", m_header->m_dwExportPoint, m_header->m_dwExportPoint - m_header->m_dwImageBase);
	printf("  Checksum    : 0x%08X\n", m_header->m_dwCheckSum);
	printf("  Sections    : %hu\n", m_header->m_wSectionCount);

	m_sectionbase = reinterpret_cast<blob_section_t*>(filebuffer + sizeof(blob_info_t) + sizeof(blob_hdr_t));

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

bool blob_algorithm::valid_info_header()
{
	if (m_info->m_dwMagic != BLOB_ALGORITHM_MAGIC)
	{
		printf("Error: Invalid blob algorithm magic number: 0x%08X\n", m_info->m_dwMagic);
		return false;
	}

	printf("Blob info header is fine.\n");

	return true;
}

bool blob_algorithm::valid_blob_data_header()
{
	if (!m_header->m_dwImageBase)
	{
		printf("Error: Blob header exposed invalid image base!\n");
		return false;
	}

	if (!m_header->m_dwExportPoint)
	{
		printf("Error: Blob header exposed invalid entry point!\n");
		return false;
	}

	if (!m_header->m_dwImportTable)
	{
		printf("Error: Blob header exposed invalid import table!\n");
		return false;
	}

	if (!m_header->m_wSectionCount)
	{
		printf("Error: Blob header exposed invalid section count!\n");
		return false;
	}

	printf("Blob data header is fine.\n");

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

	printf("Xorred file buffer with Valve's magic xor number: W (0x%02X)\n", 'W');
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

			printf("[0x%08X] Wrote %d bytes of alignment\n", (uint32_t)ofs.tellp(), mod);
			delete[] zero_buffer;
		}
	}
}
