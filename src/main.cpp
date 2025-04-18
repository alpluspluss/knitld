#include <iostream>
#include <knit/linker.hpp>

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		std::cerr << "usage: " << argv[0] << " -o <output_file> <input_files...>" << std::endl;
		return 1;
	}

	knt::MachoLinker linker;
	std::string output_path;

	for (auto i = 1; i < argc; i++)
	{
		std::string arg = argv[i];
		if (arg == "-o" && i + 1 < argc)
		{
			output_path = argv[++i];
		}
		else
		{
			if (!linker.add_input(arg))
			{
				std::cerr << "error adding input file: " << arg << std::endl;
				return 1;
			}
		}
	}

	if (output_path.empty())
	{
		std::cerr << "error: no output file specified" << std::endl;
		return 1;
	}

	if (!linker.link(output_path))
	{
		std::cerr << "error linking files" << std::endl;
		return 1;
	}

	std::cout << "successfully created " << output_path << std::endl;
	return 0;
}
