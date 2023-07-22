#include <iostream>
#include <fstream>
#include <filesystem>
#include <windows.h>

#include "decrypt.h"

void cin_get()
{
	printf("Press any key to exit the application...\n");
//	std::cin.get();
}

int main(int arc, char** argv)
{
	printf("Start\n");

	const char* file_in = argv[1];
	
	if (!file_in || arc != 2)
	{
		printf("You have to specify input file!\n");
		printf("Syntax: exefile 'input file'\n");
		return 1;
	}
	
	auto path_in = std::filesystem::path(file_in);
	auto path_out = std::filesystem::path(path_in);
	
	path_out.replace_filename(path_out.replace_extension("").filename().string() + "_dec.dll");
	
	// Directory to current exe file
	const auto us_path = std::filesystem::path(argv[0]).parent_path();
	
	printf("Input file: \"%s\"\n", path_in.string().c_str());
	
	// If the file is not found, try to search locally
	if (!std::filesystem::exists(path_in))
	{
		if (!path_in.has_extension())
			path_in.replace_extension(".dll");
	
		path_in = us_path.string() + "\\" + path_in.string();
	
		// Do this to out file as well
		path_out = us_path.string() + "\\" + path_out.string();
	
		if (!std::filesystem::exists(path_in))
		{
			printf("Error: Input file doesn't exist!\n");
			cin_get();
			return 1;
		}
	}
	
	const auto in_filesize = std::filesystem::file_size(path_in);
	
	if (!decrypt_processor::get().process_file(path_in, path_out, in_filesize))
	{
		printf("Error: Failed to decrypt the file!\n");
		cin_get();
		return 1;
	}

	printf("Success!\n");
	cin_get();
	return 0;
}
