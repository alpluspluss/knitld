/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <string>
#include <knit/mach-o.hpp>

namespace knt
{
	/* `CpuType` to `std::string_view` */
	std::string cputstr(CpuType type);

	/* `FileType` to `std::string_view` */
	std::string fttstr(FileType type);

	/* `SectionType` to `std::string_view` */
	std::string secttstr(SectionType type);

	/* `RelocationType` to `std::string_view` */
	std::string reloctstr(RelocationType reloc, CpuType cpu);
}
