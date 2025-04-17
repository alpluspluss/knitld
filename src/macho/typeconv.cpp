/* this file is a part of Knit linker project; see LICENSE for more info */

#include <string>
#include <knit/macho/typeconv.hpp>

namespace knt
{
	std::string cputstr(CpuType type)
	{
		switch (type)
		{
			case CpuType::X86:
				return "x86";
			case CpuType::X86_64:
				return "x86_64";
			case CpuType::ARM:
				return "arm";
			case CpuType::ARM64:
				return "arm64";
			case CpuType::POWERPC:
				return "powerpc";
			case CpuType::POWERPC64:
				return "powerpc64";
			default:
				return std::string(std::string("<unknown: ")
				                        + std::string("code ")
				                        + std::string(std::to_string(static_cast<std::uint32_t>(type)))
				                        + std::string(">"));
		}
	}

	std::string fttstr(FileType type)
	{
		switch (type)
		{
			case FileType::OBJECT:
				return "Object File";
			case FileType::EXECUTE:
				return "Executable";
			case FileType::FVMLIB:
				return "Fixed VM Library";
			case FileType::CORE:
				return "Core File";
			case FileType::PRELOAD:
				return "Preloaded Executable";
			case FileType::DYLIB:
				return "Dynamic Library";
			case FileType::DYLINKER:
				return "Dynamic Linker";
			case FileType::BUNDLE:
				return "Bundle";
			case FileType::DYLIB_STUB:
				return "Dynamic Library Stub";
			case FileType::DSYM:
				return "Debug Symbols";
			case FileType::KEXT_BUNDLE:
				return "Kernel Extension";
			case FileType::FILESET:
				return "File Set";
			default:
				return std::string("<unknown: "
				                        + std::string("code ")
				                        + std::string(std::to_string(static_cast<std::uint32_t>(type)))
				                        + std::string(">"));
		}
	}

	std::string secttstr(SectionType type)
	{
		switch (static_cast<std::underlying_type_t<SectionType>>(type) & 0xFF)
		{
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::REGULAR):
				return "Regular";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::ZEROFILL):
				return "Zero Fill";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::CSTRING_LITERALS):
				return "C String Literals";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::LITERAL_POINTERS):
				return "Literal Pointers";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::NON_LAZY_SYMBOL_POINTERS):
				return "Non-Lazy Symbol Pointers";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::LAZY_SYMBOL_POINTERS):
				return "Lazy Symbol Pointers";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::SYMBOL_STUBS):
				return "Symbol Stubs";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::MOD_INIT_FUNC_POINTERS):
				return "Module Init Function Pointers";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::MOD_TERM_FUNC_POINTERS):
				return "Module Term Function Pointers";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::COALESCED):
				return "Coalesced";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::GB_ZEROFILL):
				return "GB Zero Fill";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::INTERPOSING):
				return "Interposing";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::LITERALS_16B):
				return "16-byte Literals";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::DTRACE_DOF):
				return "DTrace DOF";
			case static_cast<std::underlying_type_t<SectionType>>(SectionType::LAZY_DYLIB_SYMBOL_POINTERS):
				return "Lazy Dylib Symbol Pointers";
			default:
				return std::string("<unknown: "
				                        + std::string("code ")
				                        + std::string(std::to_string(static_cast<std::uint32_t>(type)))
				                        + std::string(">"));
		}
	}

	std::string reloctstr(RelocationType reloc, const CpuType cpu)
	{
		if (cpu == CpuType::X86_64)
		{
			switch (reloc)
			{
				case RelocationType::X86_64_RELOC_UNSIGNED:
					return "X86_64_RELOC_UNSIGNED";
				case RelocationType::X86_64_RELOC_SIGNED:
					return "X86_64_RELOC_SIGNED";
				case RelocationType::X86_64_RELOC_BRANCH:
					return "X86_64_RELOC_BRANCH";
				case RelocationType::X86_64_RELOC_GOT_LOAD:
					return "X86_64_RELOC_GOT_LOAD";
				case RelocationType::X86_64_RELOC_GOT:
					return "X86_64_RELOC_GOT";
				case RelocationType::X86_64_RELOC_SUBTRACTOR:
					return "X86_64_RELOC_SUBTRACTOR";
				case RelocationType::X86_64_RELOC_SIGNED_1:
					return "X86_64_RELOC_SIGNED_1";
				case RelocationType::X86_64_RELOC_SIGNED_2:
					return "X86_64_RELOC_SIGNED_2";
				case RelocationType::X86_64_RELOC_SIGNED_4:
					return "X86_64_RELOC_SIGNED_4";
				default:
					return std::string("<unknown: "
					                        + std::string("\n\treloc-> ")
					                        + std::string(std::to_string(static_cast<std::uint32_t>(reloc)))
					                        + std::string(" | ")
					                        + std::string("cpu -> ")
					                        + std::string(cputstr(cpu))
					                        + std::string(">"));
			}
		}
		if (cpu == CpuType::ARM64)
		{
			switch (reloc)
			{
				case RelocationType::ARM64_RELOC_UNSIGNED:
					return "ARM64_RELOC_UNSIGNED";
				case RelocationType::ARM64_RELOC_SUBTRACTOR:
					return "ARM64_RELOC_SUBTRACTOR";
				case RelocationType::ARM64_RELOC_BRANCH26:
					return "ARM64_RELOC_BRANCH26";
				case RelocationType::ARM64_RELOC_PAGE21:
					return "ARM64_RELOC_PAGE21";
				case RelocationType::ARM64_RELOC_PAGEOFF12:
					return "ARM64_RELOC_PAGEOFF12";
				case RelocationType::ARM64_RELOC_GOT_LOAD_PAGE21:
					return "ARM64_RELOC_GOT_LOAD_PAGE21";
				case RelocationType::ARM64_RELOC_GOT_LOAD_PAGEOFF12:
					return "ARM64_RELOC_GOT_LOAD_PAGEOFF12";
				default:
					return std::string("<unknown: "
					                        + std::string("\n\treloc-> ")
					                        + std::string(std::to_string(static_cast<std::uint32_t>(reloc)))
					                        + std::string(" | ")
					                        + std::string("cpu -> ")
					                        + std::string(cputstr(cpu))
					                        + std::string(">"));
			}
		}
		return std::string("<unknown: ")
		                        + std::string("\n\treloc-> ")
		                        + std::string(std::to_string(static_cast<std::uint32_t>(reloc)))
		                        + std::string(" | ")
		                        + std::string("cpu -> ")
		                        + std::string(cputstr(cpu))
		                        + std::string(">");
	}
}
