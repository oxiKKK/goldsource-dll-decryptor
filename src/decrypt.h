#ifndef DECRYPT_H
#define DECRYPT_H

#pragma once

class decrypt_processor
{
public:
	static auto& get()
	{
		static decrypt_processor decrypt;
		return decrypt;
	}

public:
	bool process_file(const std::filesystem::path& file_in, const std::filesystem::path& file_out, uint32_t filesize);

private:
	// Allocation and deallocation of the file buffer
	bool allocate_buffer(uint32_t size);
	void deallocate_buffer();

	// Write built binary into new file
	bool write_to_file(const std::filesystem::path& file_out);

private:
	byte*		m_filebuffer = nullptr;
	uint32_t	m_buffer_size = NULL;
};

#endif