#ifndef DECRYPT_H
#define DECRYPT_H

#pragma once

#define FILE_IN "X:\\Programming\\MyWork\\ConsoleApplication14\\hw_enc.dll"
#define FILE_OUT "X:\\Programming\\MyWork\\ConsoleApplication14\\hw_dec.dll"

class decrypt_processor
{
public:
	static auto& get()
	{
		decrypt_processor decrypt;
		return decrypt;
	}

public:
	bool process_file(const std::filesystem::path& path, uint32_t filesize);

private:
	// Allocation and deallocation of the file buffer
	bool allocate_buffer(uint32_t size);
	void deallocate_buffer();

	// Write built binary into new file
	bool write_to_file();

private:
	byte*		m_filebuffer = nullptr;
	uint32_t	m_buffer_size = NULL;
};

#endif