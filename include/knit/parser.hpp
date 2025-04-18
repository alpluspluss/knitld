/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <fstream>
#include <string_view>
#include <vector>
#include <knit/dwarf.hpp>
#include <knit/dyld.hpp>
#include <knit/mach-o.hpp>

namespace knt
{
	class MachoParser
	{
	public:
		explicit MachoParser(std::string_view path);

		~MachoParser();

		void parse();

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

		[[nodiscard]]
		bool has_dynamic_linking() const;

		[[nodiscard]]
		bool has_chained_fixups() const;

		[[nodiscard]]
		const DynamicLinkingInfo& dynamic_linking_info() const;

		[[nodiscard]]
		bool has_dwarf() const;

		[[nodiscard]]
		const DwarfInfo& dwarf_info() const;

		[[nodiscard]]
		const DwarfSection* dwarf_section(DwarfSectionType type) const;

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

		bool dynlinking;
		bool chainfixups;
		DynamicLinkingInfo dyldinfo;
		bool contains_dwarf;
		DwarfInfo dwarfinfo;

		void parse_dynamic_linking();

		void parse_rebase_info();

		void parse_bind_info(std::uint32_t offset, std::uint32_t size, std::vector<BindInfo>& binds);

		void parse_lazy_bind_info();

		void parse_weak_bind_info();

		void parse_chained_fixups();
	};
}
