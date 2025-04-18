/* this file is a part of Knit linker project; see LICENSE for more info */

#include <knit/dwarf.hpp>

namespace knt
{
	DwarfSectionType sectnamettype(const std::string &name)
	{
		if (name == "__debug_info")
			return DwarfSectionType::DEBUG_INFO;
		if (name == "__debug_abbrev")
			return DwarfSectionType::DEBUG_ABBREV;
		if (name == "__debug_line")
			return DwarfSectionType::DEBUG_LINE;
		if (name == "__debug_str")
			return DwarfSectionType::DEBUG_STR;
		if (name == "__debug_ranges")
			return DwarfSectionType::DEBUG_RANGES;
		if (name == "__debug_pubnames")
			return DwarfSectionType::DEBUG_PUBNAMES;
		if (name == "__debug_pubtypes")
			return DwarfSectionType::DEBUG_PUBTYPES;
		if (name == "__debug_frame")
			return DwarfSectionType::DEBUG_FRAME;
		if (name == "__debug_loc")
			return DwarfSectionType::DEBUG_LOC;
		if (name == "__debug_macinfo")
			return DwarfSectionType::DEBUG_MACINFO;
		if (name == "__debug_types")
			return DwarfSectionType::DEBUG_TYPES;
		if (name == "__debug_aranges")
			return DwarfSectionType::DEBUG_ARANGES;
		return DwarfSectionType::DEBUG_UNKNOWN;
	}

	bool is_dwarf_section(const std::string &name)
	{
		return name.find("__debug_") == 0;
	}
}
