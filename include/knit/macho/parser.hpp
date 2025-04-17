/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <fstream>
#include <string_view>
#include <vector>
#include <knit/mach-o.hpp>

namespace knt
{
	class MachoParser
	{
	public:
		explicit MachoParser(std::string_view path);

		~MachoParser();

		[[nodiscard]]
		bool is_macho() const;

		[[nodiscard]]
		std::size_t sect_count() const;

		[[nodiscard]]
		std::string sect_name(std::size_t index) const;

		[[nodiscard]]
		const std::vector<std::uint8_t>& sect_data(std::size_t index) const;

		[[nodiscard]]
		const std::vector<std::uint8_t>& sect_data(std::string_view segname, std::string_view sectname) const;

		[[nodiscard]]
		const SectionInfo* sect(std::uint8_t index) const;

		[[nodiscard]]
		const SymbolInfo* find_symbol(std::string_view name) const;

		[[nodiscard]]
		const std::vector<SegmentInfo>& segments() const;

		[[nodiscard]]
		const std::vector<SymbolInfo>& symbols() const;

		[[nodiscard]]
		const std::vector<IndirectSymbolInfo>& indirect_symbols() const;

		[[nodiscard]]
		bool has_symbol_table() const;

		[[nodiscard]]
		bool has_dysym_table() const;

		[[nodiscard]]
		bool has_dyld_info_cmd() const;

		[[nodiscard]]
		CpuType cpu_type() const;

		[[nodiscard]]
		FileType file_type() const;

		[[nodiscard]]
		std::uint32_t flags() const;

	private:
		std::string path;
		std::vector<std::uint8_t> file;
		bool is_valid;
		bool is_fat;
		bool is_64bit;
		bool has_symtab;
		bool has_dysym_tab;
		bool has_dyld_info;
		CpuType cpu;
		FileType filetype;
		std::uint32_t num_cmds;
		std::uint32_t mach_flags;
		bool swap_bytes;

		std::vector<FatArch> fat_archs;
		std::vector<SegmentInfo> segs;
		std::vector<SymbolInfo> syms;
		std::vector<IndirectSymbolInfo> indirect_syms;
		std::vector<std::string> dylibs;
		DyldInfoCommand dyld_info;
		std::string uuid;
		std::string min_version;
		std::uint64_t entry_point;

		SymtabCommand symtab_cmd;
		DysymtabCommand dysymtab_cmd;

		void parse();
	};
}
