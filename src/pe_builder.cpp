#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "blob_algorithm.h"
#include "pe_builder.h"

#define ALIGN_AS(num, align) (((num) + ((align) - 1)) & (~((align) - 1)))

// Pre-defined ordinary sections that are static for all Dlls
static const ordinary_section_data_t ordinary_sections[] = {
	{ ".text",  IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
	{ ".rdata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
	{ ".data",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
	{ ".rsrc",  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE },
	{ NULL, NULL },
};

#define ORD_SIZE (ARRAYSIZE(ordinary_sections) - 1)

// The order of sections inside a pe file should be same across
// all encrypted Valve dlls.
#define ORD_SEC_TEXT	0
#define ORD_SEC_RDATA	1
#define ORD_SEC_DATA	2
#define ORD_SEC_RSRC	3

// Section with rw & uninitialized data characteristic we count as an ordinary one
#define ORDINARY_SCN_CHARACTERISTICS (IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE)

// This routine is placed right after the cos header and contains
// "This program cannot be run in DOS mode." text
static const char dos_stub[] =
	"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x54\x68"
	"\x69\x73\x20\x70\x72\x6F\x67\x72\x61\x6D\x20\x63\x61\x6E\x6E\x6F"
	"\x74\x20\x62\x65\x20\x72\x75\x6E\x20\x69\x6E\x20\x44\x4F\x53\x20"
	"\x6D\x6F\x64\x65\x2E\x0D\x0D\x0A\x24\x00\x00\x00\x00\x00\x00\x00"
	"\xDB\xD6\xCC\x61\x9F\xB7\xA2\x32\x9F\xB7\xA2\x32\x9F\xB7\xA2\x32"
	"\xE4\xAB\xAE\x32\x97\xB7\xA2\x32\xF0\xA8\xA9\x32\x90\xB7\xA2\x32"
	"\x1C\xAB\xAC\x32\xAE\xB7\xA2\x32\xF0\xA8\xA8\x32\x31\xB7\xA2\x32"
	"\xC0\x95\xA8\x32\x9E\xB7\xA2\x32\x65\x93\xBB\x32\x9D\xB7\xA2\x32"
	"\xC0\x95\xA9\x32\xB1\xB7\xA2\x32\x18\xAB\xA0\x32\xB9\xB7\xA2\x32"
	"\x70\x95\x92\x32\x9E\xB7\xA2\x32\x9F\xB7\xA3\x32\x6C\xB7\xA2\x32"
	"\xFD\xA8\xB1\x32\x8E\xB7\xA2\x32\xE1\x95\xBE\x32\x9C\xB7\xA2\x32"
	"\xAC\x95\x87\x32\x9B\xB7\xA2\x32\xCB\x94\x93\x32\xAB\xB7\xA2\x32"
	"\xCB\x94\x92\x32\xF2\xB7\xA2\x32\x58\xB1\xA4\x32\x9E\xB7\xA2\x32"
	"\x9F\xB7\xA2\x32\x80\xB7\xA2\x32\x60\x97\xA6\x32\x8C\xB7\xA2\x32"
	"\x52\x69\x63\x68\x9F\xB7\xA2\x32\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// This stub is Valve's one and it is in most of Valve's modules.
static const char valve_stub[] =
	"\x56\x4C\x56\x00\x01\x00\x00\x00\x59\xF0\x18\x00\xA7\x8D\x3D\x5F"
	"\x50\xFD\x83\x01\xE0\xD5\xF7\x8B\x91\xEE\x1C\x6A\xC5\xE2\x3C\x77"
	"\xF7\x6F\xE9\x3D\xE8\x45\x9F\xB1\xCE\x9C\xC1\x99\x6F\x3B\x23\xCE"
	"\x4D\x75\xA2\xBA\x50\xC0\x8F\x6B\x6B\xC6\x04\xA0\xCB\x83\xAB\x9C"
	"\x6A\x77\x43\x55\x95\xFE\x60\x40\xA0\x4C\xAB\x59\xCA\x29\xE0\x35"
	"\xA7\xBD\x2A\x22\xCD\x4B\x33\xA7\xAF\xA3\x1B\x64\xEE\xD5\x6E\x82"
	"\x5E\xE9\x0D\x8D\x74\xB7\x30\x56\xF2\x82\x6B\x9E\xE5\xD7\x18\xA0"
	"\xFF\x0E\x88\x3C\x97\x50\xD3\x30\x19\x10\xE1\xCF\x26\xFC\xFE\xFE"
	"\xE2\xF7\xFF\x12\x22\x93\x78\x0A\x98\x2D\x29\x3E\xF2\x7F\xD6\x99"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	"\x00\x00\x00\x00\x00\x00\x00";

// Get offset relative to the base address of a section
uint32_t pe_builder::rva_to_u32_offset(blob_section_t* sectionbase, uint16_t num_sections, uint32_t rva)
{
	for (uint16_t i = 0; i < num_sections; i++)
	{
		const auto sec = &sectionbase[i];

		// Check if the address is inside boundary of this section, if
		// yes, proceed further
		if (sec->m_dwVirtualAddress > rva || (sec->m_dwVirtualAddress + sec->m_dwVirtualSize) <= rva)
			continue;

		// Get the relative address starting by this section
		return (rva - sec->m_dwVirtualAddress) + sec->m_dwDataAddress;
	}

	return NULL;
}

void pe_builder::build_pe_header(byte* filebuffer, blob_hdr_t* blob_hdr, blob_section_t* blob_sections)
{
	printf("Building PE header...\n");

	memset(&m_dos_hdr, NULL, sizeof(m_dos_hdr));

	// This data seems to be constant stable
	m_dos_hdr.e_magic = IMAGE_DOS_SIGNATURE;
	m_dos_hdr.e_cblp = 144;
	m_dos_hdr.e_cp = 3;
	m_dos_hdr.e_crlc = 0;
	m_dos_hdr.e_cparhdr = 4;
	m_dos_hdr.e_minalloc = 0;
	m_dos_hdr.e_maxalloc = 0xffff;
	m_dos_hdr.e_ss = 0;
	m_dos_hdr.e_sp = 184;
	m_dos_hdr.e_csum = 0;
	m_dos_hdr.e_ip = 0;
	m_dos_hdr.e_cs = 0;
	m_dos_hdr.e_lfarlc = 64;
	m_dos_hdr.e_ovno = 0;
	m_dos_hdr.e_oemid = 0;
	m_dos_hdr.e_oeminfo = 0;
	m_dos_hdr.e_lfanew = sizeof(IMAGE_DOS_HEADER) + sizeof(dos_stub);

	printf("  Size of DOS stub program: 0x%08X\n", sizeof(dos_stub));
	printf("  File address to NT headers: 0x%08X\n", m_dos_hdr.e_lfanew);

	printf("DOS header done...\n");

	memset(&m_nt_headers, NULL, sizeof(m_nt_headers));

	// Build NT headers
	m_nt_headers.Signature = IMAGE_NT_SIGNATURE;

	// Build file header
	m_nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	m_nt_headers.FileHeader.NumberOfSections = blob_hdr->m_wSectionCount;
	m_nt_headers.FileHeader.TimeDateStamp = time(nullptr);
	m_nt_headers.FileHeader.PointerToSymbolTable = 0;
	m_nt_headers.FileHeader.NumberOfSymbols = 0;
	m_nt_headers.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	m_nt_headers.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_DLL;

	printf("  Number of PE sections: %d\n", m_nt_headers.FileHeader.NumberOfSections);
	printf("  Set FileHeader timestamp: %s", timestamp_as_string(m_nt_headers.FileHeader.TimeDateStamp).c_str());
	printf("  Size of optional header: %d/0x%08X bytes\n", m_nt_headers.FileHeader.SizeOfOptionalHeader, m_nt_headers.FileHeader.SizeOfOptionalHeader);
	printf("  File header characteristics flags: 0x%08X\n", m_nt_headers.FileHeader.Characteristics);

	printf("NT file header done...\n");

	// Build optional header
	m_nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
	m_nt_headers.OptionalHeader.MajorLinkerVersion = 6;
	m_nt_headers.OptionalHeader.MinorLinkerVersion = 0;
	m_nt_headers.OptionalHeader.AddressOfEntryPoint = blob_hdr->m_dwEntryPoint - blob_hdr->m_dwImageBase; // VA to image's entry point
	m_nt_headers.OptionalHeader.BaseOfCode = blob_sections[ORD_SEC_TEXT].m_dwVirtualAddress - blob_hdr->m_dwImageBase; // First is always .text
	m_nt_headers.OptionalHeader.BaseOfData = blob_sections[ORD_SEC_RDATA].m_dwVirtualAddress - blob_hdr->m_dwImageBase; // Second is always .rdata
	m_nt_headers.OptionalHeader.ImageBase = blob_hdr->m_dwImageBase;
	m_nt_headers.OptionalHeader.SectionAlignment = 4096; // The alignment (in bytes) of sections when they are loaded into memory.
	m_nt_headers.OptionalHeader.FileAlignment = 4096; // The alignment factor (in bytes) that is used to align the raw data of sections in the image file
	m_nt_headers.OptionalHeader.MajorOperatingSystemVersion = 4;
	m_nt_headers.OptionalHeader.MinorOperatingSystemVersion = 0;
	m_nt_headers.OptionalHeader.MajorImageVersion = 0;
	m_nt_headers.OptionalHeader.MinorImageVersion = 0;
	m_nt_headers.OptionalHeader.MajorSubsystemVersion = 4;
	m_nt_headers.OptionalHeader.MinorSubsystemVersion = 0;
	m_nt_headers.OptionalHeader.Win32VersionValue = NULL;
	m_nt_headers.OptionalHeader.SizeOfHeaders = 4096; // Usually this
	m_nt_headers.OptionalHeader.CheckSum = blob_hdr->m_dwCheckSum; // Not sure about this?
	m_nt_headers.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	m_nt_headers.OptionalHeader.DllCharacteristics = NULL;
	m_nt_headers.OptionalHeader.SizeOfStackReserve = 4096 * 256;
	m_nt_headers.OptionalHeader.SizeOfStackCommit = 4096;
	m_nt_headers.OptionalHeader.SizeOfHeapReserve = 4096 * 256;
	m_nt_headers.OptionalHeader.SizeOfHeapCommit = 4096;
	m_nt_headers.OptionalHeader.LoaderFlags = NULL;
	m_nt_headers.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	printf("  Relative address to entry point: 0x%08X\n", m_nt_headers.OptionalHeader.AddressOfEntryPoint);
	printf("  Relative address to code segment: 0x%08X\n", m_nt_headers.OptionalHeader.BaseOfCode);
	printf("  Relative address to data segment: 0x%08X\n", m_nt_headers.OptionalHeader.BaseOfData);
	printf("  Image base address: 0x%08X\n", m_nt_headers.OptionalHeader.ImageBase);
	printf("  File section alignment: %d/0x%08X bytes\n", m_nt_headers.OptionalHeader.FileAlignment, m_nt_headers.OptionalHeader.FileAlignment);
	printf("  PE headers alignment: %d/0x%08X bytes\n", m_nt_headers.OptionalHeader.SizeOfHeaders, m_nt_headers.OptionalHeader.SizeOfHeaders);

	printf("NT optional header done...\n");

	// File offset or file pointer to the raw data of sections.
	// Section raw data is stored continuosly inside the file, right 
	// after the PE headers (0x1000 file offset).
	uint32_t sec_fileoffset = m_nt_headers.OptionalHeader.SizeOfHeaders;

	printf("Building section table...\n");

	// Build section data for OPT header
	for (uint16_t i = 0; i < blob_hdr->m_wSectionCount; i++)
	{
		blob_section_t* sec = &blob_sections[i];

		char sec_name[IMAGE_SIZEOF_SHORT_NAME];

		// We can get the name from the ordinary section table
		if (i < ORD_SIZE)
			strncpy(sec_name, ordinary_sections[i].m_szName, IMAGE_SIZEOF_SHORT_NAME);
		else
			snprintf(sec_name, IMAGE_SIZEOF_SHORT_NAME, "sec%hu", i);

		printf("%s:\n", sec_name);

		uint32_t flag = (i < ORD_SIZE) ? ordinary_sections[i].m_dwCharacteristics : ORDINARY_SCN_CHARACTERISTICS;

		// Structures has to be aligned to this boudary
		const uint32_t file_alignment = m_nt_headers.OptionalHeader.FileAlignment;

		// Increase individual section data
		m_nt_headers.OptionalHeader.SizeOfImage += ALIGN_AS(sec->m_dwVirtualSize, file_alignment);

		// .text
		if (flag & IMAGE_SCN_CNT_CODE)
		{
			printf("  Code section %d/0x%08X bytes\n", sec->m_dwVirtualSize, sec->m_dwVirtualSize);
			m_nt_headers.OptionalHeader.SizeOfCode += ALIGN_AS(sec->m_dwVirtualSize, file_alignment);
		}

		// .rdata
		if (flag & IMAGE_SCN_CNT_INITIALIZED_DATA)
		{
			printf("  Initialized data section %d/0x%08X bytes\n", sec->m_dwVirtualSize, sec->m_dwVirtualSize);
			m_nt_headers.OptionalHeader.SizeOfInitializedData += ALIGN_AS(sec->m_dwVirtualSize, file_alignment);
		}

		// .bss
		if (flag & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
			printf("  Unitialized data section %d/0x%08X bytes\n", sec->m_dwVirtualSize, sec->m_dwVirtualSize);
			m_nt_headers.OptionalHeader.SizeOfUninitializedData += ALIGN_AS(sec->m_dwVirtualSize, file_alignment);
		}

		// Build PE header sections
		IMAGE_SECTION_HEADER pe_sec;
		memset(&pe_sec, NULL, sizeof(pe_sec));
		
		// Section name we get from ordinary sections
		strcpy((char*)pe_sec.Name, sec_name);
		
		// Build up this pe_sec data
		pe_sec.Misc.VirtualSize = sec->m_dwVirtualSize;
		pe_sec.VirtualAddress = sec->m_dwVirtualAddress - blob_hdr->m_dwImageBase;
		pe_sec.SizeOfRawData = ALIGN_AS(sec->m_dwDataSize, m_nt_headers.OptionalHeader.FileAlignment); // Must be aligned to the FileAlignment value
		// For uninitialized data this is always zero
		pe_sec.PointerToRawData = (flag & IMAGE_SCN_CNT_UNINITIALIZED_DATA) ? 0 : sec_fileoffset; // File pointer to the raw data
		pe_sec.PointerToRelocations = 0; // File pointer
		pe_sec.PointerToLinenumbers = 0;
		pe_sec.NumberOfRelocations = 0;
		pe_sec.NumberOfLinenumbers = 0;
		pe_sec.Characteristics = (i < ORD_SIZE) ? ordinary_sections[i].m_dwCharacteristics : ORDINARY_SCN_CHARACTERISTICS;
		
		printf("  Section RVA: 0x%08X\n", pe_sec.VirtualAddress);
		printf("  Section at file offset: 0x%08X\n", pe_sec.PointerToRawData);
		printf("  Characteristics: 0x%08X\n", pe_sec.Characteristics);

		// Move to next section
		sec_fileoffset += ALIGN_AS(sec->m_dwDataSize, 4096);
		
		m_pe_section_table.emplace_back(pe_sec);
	}

	m_nt_headers.OptionalHeader.SizeOfImage += m_nt_headers.OptionalHeader.SizeOfHeaders;

	printf("Total size of image: %d/0x%08X bytes\n", m_nt_headers.OptionalHeader.SizeOfImage, m_nt_headers.OptionalHeader.SizeOfImage);

	build_data_directories(filebuffer, blob_hdr, blob_sections);

	printf("Building PE header finish\n");
}

void pe_builder::build_data_directories(byte* filebuffer, blob_hdr_t* blob_hdr, blob_section_t* blob_sections)
{
	printf("Building data directories...\n");

	auto idd = &m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto edd = &m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto rdd = &m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	auto iatdd = &m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

	printf("Building imports...\n");
	process_imports(filebuffer, idd, iatdd, blob_hdr, blob_sections);

	edd->VirtualAddress = 0x001AEC50;
	edd->Size = 0x0000714C;

	rdd->VirtualAddress = 0x01273000;
	rdd->Size = 0x00001000;

	//auto edd = &m_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	//
	//printf("Building exports...\n");
	//process_exports(filebuffer, edd, blob_hdr, blob_sections);
	//print_data_directory("Export", edd);
}

void pe_builder::print_data_directory(const char* name, PIMAGE_DATA_DIRECTORY idd)
{
	printf("--- %s descriptor ---\n", name);
	printf("  VirtualAddress: 0x%08X\n", idd->VirtualAddress);
	printf("  Size:           0x%08X\n", idd->Size);
}

void pe_builder::process_imports(byte* filebuffer, IMAGE_DATA_DIRECTORY* idd, IMAGE_DATA_DIRECTORY* iatdd, blob_hdr_t* blob_hdr, blob_section_t* blob_sections)
{
	uint32_t iid_file_pointer = rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, blob_hdr->m_dwImportTable);
	auto iid = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(filebuffer + iid_file_pointer);

	// IAT data
	uint32_t iat_first_thunk = ~0, iat_last_thunk = 0;

	printf("Found import descriptor at file offset 0x%08X\n", iid_file_pointer);
	printf("Processing imports...\n");
	
	uint32_t num_iid = 0, num_thunks = 0;
	while (iid->Name)
	{
		// FirstThunk is a RVA from the image base, unlike the m_dwImportTable, which is a VA containing the image base.
		// Same applies for Name. In this case, we have to add the image base to the calculation.
		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
			filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, iid->FirstThunk + blob_hdr->m_dwImageBase));

		// RVA from image base
		auto name = reinterpret_cast<const char*>(
			filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, iid->Name + blob_hdr->m_dwImageBase));
		
		// Get the first thunk address of where the iat is
		if (iid->FirstThunk < iat_first_thunk)
			iat_first_thunk = iid->FirstThunk;

		printf("  %-16s", name);
		
		uint32_t this_idd_thunks = 0;
		while (thunk->u1.AddressOfData)
		{
			// Name of the thunk is also an RVA from the image base
			auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
				filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, thunk->u1.AddressOfData + blob_hdr->m_dwImageBase));
			
			auto ordinal = thunk->u1.Ordinal;
				
			thunk++;
			this_idd_thunks++; // counting only for this descriptor entry
		}

		// Get the last thunk address
		const uint32_t thunk_size = (sizeof(IMAGE_IMPORT_BY_NAME) * (this_idd_thunks + 1)); // Don't forget the null thunk
		if (iid->FirstThunk + thunk_size > iat_last_thunk)
			iat_last_thunk = iid->FirstThunk + thunk_size;

		printf(" (%-3d thunk%s)\n", this_idd_thunks, this_idd_thunks > 1 ? "s" : " ");

		iid++;
		num_thunks += this_idd_thunks; // overall count
		num_iid++;
	}

	printf("Found %d import descriptors\n", num_iid);
	printf("Found %d thunk routines\n", num_thunks);

	// IDD
	idd->VirtualAddress = blob_hdr->m_dwImportTable - blob_hdr->m_dwImageBase; // VA to the image base
	idd->Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (num_iid + 1); // + 1 for the null descriptor at the end
	print_data_directory("Import", idd);

	constexpr uint32_t a = offsetof(IMAGE_NT_HEADERS, OptionalHeader);
	constexpr uint32_t b = a + offsetof(IMAGE_OPTIONAL_HEADER, DataDirectory);

	printf("- import table found: %08x of %u bytes\n", blob_hdr->m_dwImportTable - blob_sections[1].m_dwVirtualAddress, idd->Size);

	// IATDD
	iatdd->VirtualAddress = iat_first_thunk; // RVA to the first thunk
	iatdd->Size = iat_last_thunk - iat_first_thunk;
	print_data_directory("Import Address Table", iatdd);

	printf("  %d entries inside IAT\n", iatdd->Size / sizeof(DWORD));
}

void pe_builder::process_exports(byte* filebuffer, IMAGE_DATA_DIRECTORY* edd, blob_hdr_t* blob_hdr, blob_section_t* blob_sections)
{
#if 0
	uint32_t ied_file_pointer = rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, blob_hdr->m_dwImportTable);
	auto ied = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(filebuffer + ied_file_pointer);

	printf("Found import descriptor at file offset 0x%08X\n", iid_file_pointer);
	printf("Processing imports...\n");

	uint32_t num_iid = 0, num_thunks = 0;
	while (iid->Name)
	{
		// FirstThunk is a RVA from the image base, unlike the m_dwImportTable, which is a VA containing the image base.
		// Same applies for Name. In this case, we have to add the image base to the calculation.
		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
			filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, iid->FirstThunk + blob_hdr->m_dwImageBase));

		// RVA from image base
		auto name = reinterpret_cast<const char*>(
			filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, iid->Name + blob_hdr->m_dwImageBase));

		printf("  %-16s", name);

		uint32_t this_idd_thunks = 0;
		while (thunk->u1.AddressOfData)
		{
			// Name of the thunk is also an RVA from the image base
			auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
				filebuffer + rva_to_u32_offset(blob_sections, blob_hdr->m_wSectionCount, thunk->u1.AddressOfData + blob_hdr->m_dwImageBase));

			auto ordinal = thunk->u1.Ordinal;

#if 0
			// Imports can be accessed either by name, or an ordinal.
			if (IMAGE_SNAP_BY_ORDINAL32(ordinal))
			{
				printf("  %hu\n", IMAGE_ORDINAL32(ordinal));
			}
			else
			{
				printf("  %s\n", (const char*)name->Name);
			}
#endif

			thunk++;
			num_thunks++;
			this_idd_thunks++; // counting only for this descriptor entry
		}

		printf(" (%-3d thunk%s)\n", this_idd_thunks, this_idd_thunks > 1 ? "s" : " ");

		iid++;
		num_iid++;
	}

	printf("Found %d import descriptors\n", num_iid);
	printf("Found %d thunk routines\n", num_thunks);

	idd->VirtualAddress = blob_hdr->m_dwImportTable - blob_hdr->m_dwImageBase; // VA to the image base
	idd->Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * (num_iid + 1); // + 1 for the null descriptor at the end
#endif
}

void pe_builder::write_dos_header(std::ofstream& ofs)
{
	ofs.write((const char*)&m_dos_hdr, sizeof(IMAGE_DOS_HEADER));

	printf("[0x%08X] Wrote DOS header\n", (uint32_t)ofs.tellp());

	ofs.write(dos_stub, sizeof(dos_stub));

	printf("[0x%08X] Wrote Valve (DOS) stub\n", (uint32_t)ofs.tellp());

	ofs.write((const char*)&m_nt_headers, sizeof(IMAGE_NT_HEADERS));

	printf("[0x%08X] Wrote NT headers\n", (uint32_t)ofs.tellp());
}

void pe_builder::write_pe_section_tables(std::ofstream& ofs)
{
	for (uint16_t i = 0; i < m_pe_section_table.size(); i++)
	{
		auto pe_sec_table = &m_pe_section_table[i];

		// Write this section to the output file
		ofs.write((const char*)pe_sec_table, sizeof(IMAGE_SECTION_HEADER));

		printf("[0x%08X] Wrote %s section table\n", (uint32_t)ofs.tellp(), (const char*)pe_sec_table->Name);
	}

	// In the end there's alignment up to 0x1000. This is
	// just for the PE header at the start of the image.
	// What follows is the actual image (raw) data.
	const uint32_t size_of_pe_hdrs = m_nt_headers.OptionalHeader.SizeOfHeaders;

	byte* zero_buffer = new byte[size_of_pe_hdrs];
	memset(zero_buffer, NULL, size_of_pe_hdrs);

	// Padding bytes to write
	uint32_t bytes_to_write = size_of_pe_hdrs - ofs.tellp();

	ofs.write((const char*)zero_buffer, bytes_to_write);

	printf("[0x%08X] Wrote %d bytes of padding for PE headers\n", (uint32_t)ofs.tellp(), bytes_to_write);
	delete[] zero_buffer;
}

std::string pe_builder::timestamp_as_string(std::time_t timestamp)
{
	const auto gmt = std::gmtime(&timestamp);
	if (gmt)
		return std::asctime(gmt);

	return "Unknown";
}