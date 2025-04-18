/* this file is a part of Knit linker project; see LICENSE for more info */

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <knit/dwarf.hpp>
#include <knit/mach-o.hpp>
#include <knit/parser.hpp>
#include <knit/typeconv.hpp>

void print_help(const char *program_name)
{
	std::cout << "usage: " << program_name << " <macho-file> [options]" << std::endl;
	std::cout << "options:" << std::endl;
	std::cout << "  --help, -h       show this help message" << std::endl;
	std::cout << "  --all, -a        show all information" << std::endl;
	std::cout << "  --segments, -s   show segments and sections" << std::endl;
	std::cout << "  --symbols, -y    show symbol tables" << std::endl;
	std::cout << "  --dyld, -d       show dynamic linking information" << std::endl;
	std::cout << "  --dwarf, -w      show DWARF debug information" << std::endl;
	std::cout << "  --chain, -c      show chained fixups information" << std::endl;
}

void print_segments(const knt::MachoParser &parser)
{
	const auto &segments = parser.segments();
	std::cout << "\nsegments: " << segments.size() << std::endl;
	for (const auto &seg: segments)
	{
		std::cout << "  " << seg.name;
		std::cout << " (vm: 0x" << std::hex << seg.vmaddr << " - 0x"
				<< (seg.vmaddr + seg.vmsize) << std::dec << ")" << std::endl;

		if (!seg.sections.empty())
		{
			std::cout << "    sections:" << std::endl;
			for (const auto &sect: seg.sections)
			{
				std::cout << "      " << sect.sectname;
				std::cout << " (vm: 0x" << std::hex << sect.addr;
				std::cout << ", size: 0x" << sect.size << std::dec << ")" << std::endl;
				if (sect.nreloc > 0)
				{
					std::cout << "        relocations: " << sect.nreloc << std::endl;
					for (const auto &reloc: sect.relocations)
					{
						std::cout << "          address: 0x" << std::hex << reloc.r_address;
						std::cout << ", Type: " << reloctstr(static_cast<knt::RelocationType>(reloc.r_type),
						                                          parser.cpu_type());
						if (reloc.r_extern && reloc.r_symbolnum < parser.symbols().size())
							std::cout << ", Symbol: " << parser.symbols()[reloc.r_symbolnum].name;

						std::cout << std::dec << std::endl;
					}
				}
			}
		}
	}
}

void print_symbols(const knt::MachoParser &parser)
{
	if (parser.has_symbol_table())
	{
		const auto &symbols = parser.symbols();
		std::vector<const knt::SymbolInfo *> defined_global;
		std::vector<const knt::SymbolInfo *> undefined;
		std::vector<const knt::SymbolInfo *> local;
		for (const auto &sym: symbols)
		{
			if (sym.is_undefined)
				undefined.push_back(&sym);
			else if (sym.is_extern)
				defined_global.push_back(&sym);
			else
				local.push_back(&sym);
		}

		std::cout << "\nsymbols:" << std::endl;
		if (!defined_global.empty())
		{
			std::cout << "  defined global: " << defined_global.size() << std::endl;
			for (const auto *sym: defined_global)
			{
				std::cout << "    " << sym->name;
				std::cout << " (0x" << std::hex << sym->value << std::dec << ")";
				if (sym->sect > 0)
					std::cout << " [" << parser.sect_name(sym->sect) << "]";
				std::cout << std::endl;
			}
		}

		if (!undefined.empty())
		{
			std::cout << "  undefined: " << undefined.size() << std::endl;
			for (const auto *sym: undefined)
			{
				std::cout << "    " << sym->name << std::endl;
			}
		}

		if (!local.empty())
			std::cout << "  local: " << local.size() << std::endl;
	}

	if (const auto &indirect_syms = parser.indirect_symbols();
		!indirect_syms.empty())
	{
		std::cout << "\nindirect symbols: " << indirect_syms.size() << std::endl;
		for (size_t i = 0; i < indirect_syms.size(); i++)
		{
			if (i % 8 == 0)
			{
				std::cout << "\n  ";
			}
			const auto &sym = indirect_syms[i];
			if (sym.symbol_index == 0x80000000)
			{
				std::cout << "INDIRECT_SYMBOL_LOCAL ";
			}
			else if (sym.symbol_index == 0x40000000)
			{
				std::cout << "INDIRECT_SYMBOL_ABS ";
			}
			else if (!sym.symbol_name.empty())
			{
				std::cout << sym.symbol_name << " ";
			}
			else
			{
				std::cout << "[" << sym.symbol_index << "] ";
			}
		}
		std::cout << std::endl;
	}
}

void print_dyld_info(const knt::MachoParser &parser)
{
	if (!parser.has_dynamic_linking())
	{
		std::cout << "\nno dynamic linking information found" << std::endl;
		return;
	}

	const auto &dyld_info = parser.dynamic_linking_info();

	std::cout << "\ndynamic linking information:" << std::endl;
	if (!dyld_info.imported_libraries.empty())
	{
		std::cout << "  imported libraries: " << dyld_info.imported_libraries.size() << std::endl;
		for (const auto &lib: dyld_info.imported_libraries)
		{
			std::cout << "    " << lib << std::endl;
		}
	}

	if (!dyld_info.rebases.empty())
	{
		std::cout << "  rebasing Entries: " << dyld_info.rebases.size() << std::endl;
		std::cout << "    first 5 entries:" << std::endl;
		for (size_t i = 0; i < std::min<size_t>(5, dyld_info.rebases.size()); i++)
		{
			const auto &rebase = dyld_info.rebases[i];
			std::cout << "      address: 0x" << std::hex << rebase.address << std::dec;
			std::cout << ", type: ";
			switch (rebase.type)
			{
				case knt::RebaseType::POINTER:
					std::cout << "POINTER";
					break;
				case knt::RebaseType::TEXT_ABSOLUTE32:
					std::cout << "TEXT_ABSOLUTE32";
					break;
				case knt::RebaseType::TEXT_PCREL32:
					std::cout << "TEXT_PCREL32";
					break;
				default:
					std::cout << "UNKNOWN";
					break;
			}
			std::cout << std::endl;
		}
	}

	// Display binding info
	if (!dyld_info.binds.empty())
	{
		std::cout << "  binding Entries: " << dyld_info.binds.size() << std::endl;
		std::cout << "    first 5 entries:" << std::endl;
		for (size_t i = 0; i < std::min<size_t>(5, dyld_info.binds.size()); i++)
		{
			const auto &bind = dyld_info.binds[i];
			std::cout << "      symbol: " << bind.symbol_name;
			std::cout << ", address: 0x" << std::hex << bind.address << std::dec;
			if (bind.addend != 0)
				std::cout << ", addend: " << bind.addend;
			if (bind.symbol_flags & static_cast<uint8_t>(knt::BindSymbolFlags::WEAK_IMPORT))
				std::cout << " [WEAK]";
			std::cout << std::endl;
		}
	}

	if (!dyld_info.lazy_binds.empty())
	{
		std::cout << "  lazy Binding Entries: " << dyld_info.lazy_binds.size() << std::endl;
		std::cout << "    first 5 entries:" << std::endl;
		for (size_t i = 0; i < std::min<size_t>(5, dyld_info.lazy_binds.size()); i++)
		{
			const auto &bind = dyld_info.lazy_binds[i];
			std::cout << "      symbol: " << bind.symbol_name;
			std::cout << ", address: 0x" << std::hex << bind.address << std::dec << std::endl;
		}
	}

	if (!dyld_info.weak_binds.empty())
	{
		std::cout << "  weak binding entries: " << dyld_info.weak_binds.size() << std::endl;
	}
}

void print_chained_fixups(const knt::MachoParser &parser)
{
	if (!parser.has_chained_fixups())
	{
		std::cout << "\nno chained fixups information found" << std::endl;
		return;
	}

	const auto &dyld_info = parser.dynamic_linking_info();

	std::cout << "\nchained Fixups Information:" << std::endl;
	std::cout << "  version: " << dyld_info.chained_header.fixups_version << std::endl;
	std::cout << "  imports format: " << dyld_info.chained_header.imports_format << std::endl;
	std::cout << "  import count: " << dyld_info.chained_header.imports_count << std::endl;

	std::cout << "  segments with chains: " << dyld_info.chained_starts.seg_count << std::endl;
	if (!dyld_info.chained_binds.empty())
	{
		std::cout << "  chained Binding Entries: " << dyld_info.chained_binds.size() << std::endl;
		std::cout << "    first 5 entries:" << std::endl;
		for (size_t i = 0; i < std::min<size_t>(5, dyld_info.chained_binds.size()); i++)
		{
			const auto &bind = dyld_info.chained_binds[i];
			std::cout << "      symbol: " << bind.symbol_name;
			if (bind.addend != 0)
				std::cout << ", addend: " << bind.addend;
			if (bind.symbol_flags & static_cast<uint8_t>(knt::BindSymbolFlags::WEAK_IMPORT))
				std::cout << " [WEAK]";
			std::cout << std::endl;
		}
	}
}

void print_dwarf_info(const knt::MachoParser &parser)
{
	if (!parser.has_dwarf())
	{
		std::cout << "\nno DWARF debug information found" << std::endl;
		return;
	}

	const auto &[sections] = parser.dwarf_info();
	std::cout << "\nDWARF Debug Information:" << std::endl;
	std::cout << "  available DWARF sections:" << std::endl;
	for (const auto &[type, section]: sections)
	{
		if (section.size > 0)
		{
			std::string section_name;
			switch (type)
			{
				case knt::DwarfSectionType::DEBUG_INFO:
					section_name = "__debug_info";
					break;
				case knt::DwarfSectionType::DEBUG_ABBREV:
					section_name = "__debug_abbrev";
					break;
				case knt::DwarfSectionType::DEBUG_LINE:
					section_name = "__debug_line";
					break;
				case knt::DwarfSectionType::DEBUG_STR:
					section_name = "__debug_str";
					break;
				case knt::DwarfSectionType::DEBUG_RANGES:
					section_name = "__debug_ranges";
					break;
				case knt::DwarfSectionType::DEBUG_PUBNAMES:
					section_name = "__debug_pubnames";
					break;
				case knt::DwarfSectionType::DEBUG_PUBTYPES:
					section_name = "__debug_pubtypes";
					break;
				case knt::DwarfSectionType::DEBUG_FRAME:
					section_name = "__debug_frame";
					break;
				case knt::DwarfSectionType::DEBUG_LOC:
					section_name = "__debug_loc";
					break;
				case knt::DwarfSectionType::DEBUG_MACINFO:
					section_name = "__debug_macinfo";
					break;
				case knt::DwarfSectionType::DEBUG_TYPES:
					section_name = "__debug_types";
					break;
				case knt::DwarfSectionType::DEBUG_ARANGES:
					section_name = "__debug_aranges";
					break;
				default:
					section_name = "<unknown>";
					break;
			}
			std::cout << "    " << section_name << " (offset: 0x" << std::hex << section.offset
					<< ", size: 0x" << section.size << std::dec << ")" << std::endl;
		}
	}
}

void print_header_info(const knt::MachoParser &parser)
{
	std::cout << "cpu type: " << knt::cputstr(parser.cpu_type()) << std::endl;
	std::cout << "file type: " << knt::fttstr(parser.file_type()) << std::endl;
	std::cout << "flags: 0x" << std::hex << parser.flags() << std::dec << std::endl;

	if (parser.has_dynamic_linking())
		std::cout << "has dynamic linking information" << std::endl;

	if (parser.has_chained_fixups())
		std::cout << "has chained fixups" << std::endl;

	if (parser.has_dwarf())
		std::cout << "has DWARF debug information" << std::endl;
}

int main(const int argc, char *argv[])
{
	if (argc < 2)
	{
		print_help(argv[0]);
		return 1;
	}

	const std::string input_file = argv[1];

	bool show_all = false;
	bool show_segments = false;
	bool show_symbols = false;
	bool show_dyld = false;
	bool show_dwarf = false;
	bool show_chain = false;
	for (int i = 2; i < argc; i++)
	{
		std::string arg = argv[i];
		if (arg == "--help" || arg == "-h")
		{
			print_help(argv[0]);
			return 0;
		}
		if (arg == "--all" || arg == "-a")
		{
			show_all = true;
		}
		else if (arg == "--segments" || arg == "-s")
		{
			show_segments = true;
		}
		else if (arg == "--symbols" || arg == "-y")
		{
			show_symbols = true;
		}
		else if (arg == "--dyld" || arg == "-d")
		{
			show_dyld = true;
		}
		else if (arg == "--dwarf" || arg == "-w")
		{
			show_dwarf = true;
		}
		else if (arg == "--chain" || arg == "-c")
		{
			show_chain = true;
		}
		else
		{
			std::cerr << "Unknown option: " << arg << std::endl;
			print_help(argv[0]);
			return 1;
		}
	}

	if (!show_segments && !show_symbols && !show_dyld && !show_dwarf && !show_chain)
	{
		show_all = true;
	}

	knt::MachoParser parser(input_file);
	parser.parse();
	if (!parser.is_macho())
	{
		std::cerr << "error: Not a valid Mach-O file" << std::endl;
		return 1;
	}

	std::cout << "file: " << input_file << std::endl;
	print_header_info(parser);

	if (show_all || show_segments)
	{
		print_segments(parser);
	}

	if (show_all || show_symbols)
	{
		print_symbols(parser);
	}

	if (show_all || show_dyld)
	{
		print_dyld_info(parser);
	}

	if (show_all || show_chain)
	{
		print_chained_fixups(parser);
	}

	if (show_all || show_dwarf)
	{
		print_dwarf_info(parser);
	}

	return 0;
}
