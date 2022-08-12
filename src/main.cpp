#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "decrypt.h"

int main(int arc, char** argv)
{
	printf("Start\n");

	const auto path = std::filesystem::path(FILE_IN);

	printf("Input file: \"%s\"\n", path.string().c_str());

	if (!std::filesystem::exists(path))
	{
		printf("Error: Input file doesn't exist!\n");
		std::cin.get();
		return FALSE;
	}

	const auto filesize = std::filesystem::file_size(path);

	if (!decrypt_processor::get().process_file(path, filesize))
	{
		printf("Error: Failed to decrypt the file!\n");
		std::cin.get();
		return FALSE;
	}

	printf("End!\n");

	std::cin.get();
	return TRUE;
}
