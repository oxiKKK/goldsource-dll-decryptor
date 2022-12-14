#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "blob_algorithm.h"
#include "pe_builder.h"
#include "decrypt.h"

// The encrypted file always has @ character at this offset inside th file
#define AT_SIGN_CHARACTER_OFFSET 60

bool decrypt_processor::process_file(const std::filesystem::path& file_in, const std::filesystem::path& file_out, uint32_t filesize)
{
	// Read and allocate data
	std::ifstream ifs(file_in, std::ios_base::in | std::ios_base::binary);

	if (ifs.bad())
	{
		printf("Error: Failed to open the input file!\n");
		return false;
	}

	// Files smaller than this are just not gonna work
	if (filesize < 4096)
	{
		printf("Error: File has invalid length (%d bytes)\n", filesize);
		return false;
	}

	if (!allocate_buffer(filesize))
	{
		printf("Error: Failed to allocate buffer!\n");
		return false;
	}

	// Read the whole file contents
	ifs.read((char*)m_filebuffer, filesize);
	ifs.close();

	// Decrypt the buffer, gain blob information, build pe header
	if (!blob_algorithm::get().decrypt_file_buffer(m_filebuffer, m_buffer_size))
	{
		printf("Error: Failed to decrypt the file using original Valve blob algorithm!\n");
		return false;
	}

	// Write everything we've built into new file with postfix _dec.dll
	if (!write_to_file(file_out))
	{
		printf("Error: Couldn't write the output file!\n");
		return false;
	}

	// We don't need this buffer anymore
	deallocate_buffer();

	return true;
}

bool decrypt_processor::allocate_buffer(uint32_t size)
{
	m_filebuffer = reinterpret_cast<byte*>(malloc(size));

	if (!m_filebuffer)
	{
		printf("Error: Failed to allocate file buffer on heap!\n");
		return false;
	}

	m_buffer_size = size;

	printf("Allocated %d file buffer bytes\n", m_buffer_size);

	return true;
}

void decrypt_processor::deallocate_buffer()
{
	if (!m_filebuffer)
	{
		printf("Warning: Failed to deallocate null file buffer!\n");
		return;
	}

	free(m_filebuffer);
	m_filebuffer = nullptr;
}

bool decrypt_processor::write_to_file(const std::filesystem::path& file_out)
{
	std::ofstream ofs(file_out, std::ios_base::out | std::ios_base::binary);

	if (ofs.bad())
	{
		printf("Error: Failed to open the output file!\n");
		return false;
	}

	// Raw section data has to be aligned by this boundary.
	const uint32_t file_alignment = pe_builder::get().get_file_alignment();

	pe_builder::get().write_dos_header(ofs);
	pe_builder::get().write_pe_section_tables(ofs);
	blob_algorithm::get().write_section_data(m_filebuffer, file_alignment, ofs);

	ofs.close();

	printf("\nNew dll written to \"%s\"\n", file_out.filename().string().c_str());

	return true;
}
