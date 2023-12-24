#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "blob_algorithm.h"
#include "pe_builder.h"

bool blob_algorithm::decrypt_file_buffer(byte* filebuffer, uint32_t length)
{
	printf("Starting to decrypt the file...\n");

	m_fakecoff = reinterpret_cast<FakeCOFFHeader_t*>(filebuffer);

	printf("--- Blob info header ---\n");
	printf("  rgchMisc    : \"");
	for (int i = 0; i < ARRAYSIZE(m_fakecoff->rgchMisc); i++)
	{
		printf("%c", m_fakecoff->rgchMisc[i]);
	}
	printf("\"\n");
	printf("  Signature db: 0x%08X\n", m_fakecoff->dbSignature);
	printf("  Signature   : 0x%08X\n", m_fakecoff->nSignature);

	// Validate magic number
	if (!valid_info_header())
	{
		printf("Error: Bad blob info header!\n");
		return false;
	}

	// Xor the entire file buffer with 'W'
	xor_buffer(filebuffer, length);

	// Get the blob header
	m_header = reinterpret_cast<BlobHeader_t*>(filebuffer + sizeof(FakeCOFFHeader_t));
	m_header->nAddressF ^= 0x7A32BC85;
	m_header->nImageBase ^= 0x49C042D1;
	m_header->nEntryPoint -= 0x0000000C;
	m_header->nImportDir ^= 0x872C3D47;

	// Validate addresses exposed by the blob header
	if (!valid_blob_data_header())
	{
		printf("Error: Bad blob data header!\n");
		return false;
	}

	// In blob files, there's always one section+, so we increment this now
	// so we don't have to do + 1 every time we use this afterwards.
	m_header->cblobunit++;
	
	printf("--- Blob data header ---\n");
	printf("                %-10s %s\n", "VA", "RVA");
	printf("  Image base  : 0x%08X\n", m_header->nImageBase);
	printf("  Entry point : 0x%08X 0x%08X\n", m_header->nEntryPoint, m_header->nEntryPoint - m_header->nImageBase);
	printf("  Import table: 0x%08X 0x%08X\n", m_header->nImportDir, m_header->nImportDir - m_header->nImageBase);
	printf("  Export      : 0x%08X 0x%08X\n", m_header->nAddressF, m_header->nAddressF - m_header->nImageBase);
	printf("  Checksum    : 0x%08X\n", m_header->nRandom);
	printf("  Sections    : %hu\n", m_header->cblobunit);

	m_sectionbase = reinterpret_cast<BlobUnit_t*>(filebuffer + sizeof(FakeCOFFHeader_t) + sizeof(BlobHeader_t));

	for (uint16_t i = 0; i < m_header->cblobunit; i++)
	{
		BlobUnit_t* sec = &m_sectionbase[i];

		printf("--- Section %d ---\n", i);
		printf("  VA             : 0x%08X\n", sec->nAddress);
		printf("  RVA            : 0x%08X\n", sec->nAddress - m_header->nImageBase);
		printf("  Virtual size   : %d bytes (0x%08X)\n", sec->cbMemSize, sec->cbMemSize);
		printf("  Data RA        : 0x%08X\n", sec->dbOffset);
		printf("  Data size      : %d bytes (0x%08X)\n", sec->cbFileSize, sec->cbFileSize);
		printf("  Is special     : %s\n", sec->fSpecial == TRUE ? "yes" : "no");
	}

	// Build pe header for the new image
	pe_builder::get().build_pe_header(filebuffer, m_header, m_sectionbase);

	return true;
}

bool blob_algorithm::valid_info_header()
{
	if (m_fakecoff->nSignature != CLASSIC_BLOB_SIG)
	{
		printf("Error: Invalid blob algorithm magic number: 0x%08X\n", m_fakecoff->nSignature);
		return false;
	}

	printf("Blob info header is fine.\n");

	return true;
}

bool blob_algorithm::valid_blob_data_header()
{
	if (!m_header->nImageBase)
	{
		printf("Error: Blob header exposed invalid image base!\n");
		return false;
	}

	if (!m_header->nAddressF)
	{
		printf("Error: Blob header exposed invalid entry point!\n");
		return false;
	}

	if (!m_header->nImportDir)
	{
		printf("Error: Blob header exposed invalid import table!\n");
		return false;
	}

	if (!m_header->cblobunit)
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
	for (uint32_t i = sizeof(FakeCOFFHeader_t); i < length; i++)
	{
		filebuffer[i] ^= xor_char;
		xor_char += filebuffer[i] + 'W';
	}

	printf("Xorred file buffer with Valve's magic xor number: W (0x%02X)\n", 'W');
}

void blob_algorithm::write_section_data(byte* filebuffer, uint32_t file_alignment, std::ofstream& ofs)
{
	printf("[0x%08X] Writing section contents\n", (uint32_t)ofs.tellp());

	for (uint16_t i = 0; i < m_header->cblobunit; i++)
	{
		auto sec = &m_sectionbase[i];

		ofs.write((const char*)&filebuffer[sec->dbOffset], sec->cbFileSize);

		printf("[0x%08X] Wrote %d bytes for section %d\n", (uint32_t)ofs.tellp(), sec->cbFileSize, i);

		// Sections are aligned to the FileAlignment value stored inside 
		// Optional Header.
		uint32_t mod = file_alignment - (sec->cbFileSize % file_alignment);

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
