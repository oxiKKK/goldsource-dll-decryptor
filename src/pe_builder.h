#ifndef PE_BUILDER_H
#define PE_BUILDER_H

#pragma once

struct ordinary_section_data_t
{
	const char* m_szName;
	DWORD		m_dwCharacteristics;
};

class pe_builder
{
public:
	static auto& get()
	{
		static pe_builder builder;
		return builder;
	}

public:
	// Reconstructs the PE header for new image from the blob data that we have
	void build_pe_header(byte* filebuffer, blob_hdr_t* blob_hdr, blob_section_t* blob_sections);
	
	void write_dos_header(std::ofstream& ofs);
	void write_pe_section_tables(std::ofstream& ofs);

	// We have to expose this to the blob algorithm when writing section raw data.
	inline uint32_t get_file_alignment() const { return m_nt_headers.OptionalHeader.FileAlignment; }

private:
	// Building data directories from OptionalHeader
	void build_data_directories(byte* filebuffer, blob_hdr_t* blob_hdr, blob_section_t* blob_sections);
	void print_data_directory(const char* name, PIMAGE_DATA_DIRECTORY idd);

	void process_imports(byte* filebuffer, IMAGE_DATA_DIRECTORY* idd, IMAGE_DATA_DIRECTORY* iatdd, blob_hdr_t* blob_hdr, blob_section_t* blob_sections);
	void process_exports(byte* filebuffer, IMAGE_DATA_DIRECTORY* edd, blob_hdr_t* blob_hdr, blob_section_t* blob_sections);

	uint32_t rva_to_u32_offset(blob_section_t* sectionbase, uint16_t num_sections, uint32_t rva);

	// Little utility function to convert FileHeader's timestamp into actual readable string
	std::string timestamp_as_string(std::time_t timestamp);

private:
	IMAGE_DOS_HEADER					m_dos_hdr;
	IMAGE_NT_HEADERS					m_nt_headers;

	// Image sections
	std::vector<IMAGE_SECTION_HEADER>	m_pe_section_table;
};

#endif