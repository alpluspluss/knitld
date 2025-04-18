/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <map>
#include <vector>

namespace knt
{
	enum class DwarfSectionType : std::uint8_t
	{
		DEBUG_INFO, /* .debug_info; note: DIE */
		DEBUG_ABBREV, /* .debug_abbrev */
		DEBUG_LINE, /* .debug_line */
		DEBUG_STR,  /* .debug_str */
		DEBUG_RANGES, /* .debug_ranges */
		DEBUG_PUBNAMES, /* .debug_pubnames */
		DEBUG_PUBTYPES, /* .debug_pubtypes */
		DEBUG_FRAME, /* .debug_frame */
		DEBUG_LOC, /* .debug_loc */
		DEBUG_MACINFO, /* .debug_macinfo */
		DEBUG_TYPES, /* .debug_types; note: for DWARF4 compliance */
		DEBUG_ARANGES, /* .debug_aranges */
		DEBUG_UNKNOWN /* for errors and unknown stuffs */
	};

	struct DwarfSection
	{
		std::uint64_t offset;
		std::uint64_t size;
		std::vector<uint8_t> data;
	};

	struct DwarfInfo
	{
		std::map<DwarfSectionType, DwarfSection> sections;
	};

	DwarfSectionType sectnamettype(const std::string& name);

	bool is_dwarf_section(const std::string& name);
}
