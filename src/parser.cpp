/* this file is a part of Knit linker project; see LICENSE for more info */

#include <sstream>
#include <knit/dwarf.hpp>
#include <knit/dyld.hpp>
#include <knit/parser.hpp>
#include <knit/reader.hpp>

namespace knt
{
	MachoParser::MachoParser(const std::string_view path) : file(read_file(path)),
	                                                        is_valid(false),
	                                                        is_fat(false),
	                                                        is_64bit(false),
	                                                        has_symtab(false),
	                                                        has_dysym_tab(false),
	                                                        has_dyld_info(false),
	                                                        cpu(),
	                                                        filetype(),
	                                                        num_cmds(0),
	                                                        mach_flags(0),
	                                                        swap_bytes(false),
	                                                        dyld_info({}),
	                                                        entry_point(0),
	                                                        symtab_cmd({}),
	                                                        dysymtab_cmd({}),
															dynlinking(false),
															chainfixups(false),
	                                                        contains_dwarf(false)
	{
		file = read_file(path);
	}

	MachoParser::~MachoParser()
	{
		/* `file` should clean itself here */
		file.clear();
		file.shrink_to_fit();
	}

	bool MachoParser::is_macho() const
	{
		return is_valid;
	}

	std::size_t MachoParser::sect_count() const
	{
		std::size_t n = 0;
		for (const auto &s: segs)
			n += s.sections.size();
		return n;
	}

	std::string MachoParser::sect_name(const std::size_t index) const
	{
		if (index == 0)
			return "__NOSECT";

		std::size_t n = 0;
		for (const auto &s: segs)
		{
			for (const auto &sect: s.sections)
			{
				n++;
				if (n == index)
					return s.name + "," + sect.sectname;
			}
		}
		return "<unknown>";
	}

	const std::vector<std::uint8_t> &MachoParser::sect_data(const std::size_t index) const
	{
		static constexpr std::vector<uint8_t> empty;
		if (index == 0)
			return empty;

		size_t current = 0;
		for (const auto &seg: segs)
		{
			for (const auto &sect: seg.sections)
			{
				current++;
				if (current == index)
					return sect.data;
			}
		}
		return empty;
	}

	const std::vector<std::uint8_t> &MachoParser::sect_data(const std::string_view segname,
	                                                        const std::string_view sectname) const
	{
		static constexpr std::vector<std::uint8_t> empty;
		for (const auto &seg: segs)
		{
			if (seg.name == segname)
			{
				for (const auto &sect: seg.sections)
				{
					if (sect.sectname == sectname)
						return sect.data;
				}
			}
		}
		return empty;
	}

	const SectionInfo *MachoParser::sect(std::uint8_t index) const
	{
		if (index == 0)
			return nullptr;

		size_t current = 0;
		for (const auto &seg: segs)
		{
			for (const auto &sect: seg.sections)
			{
				current++;
				if (current == index)
					return &sect;
			}
		}
		return nullptr;
	}

	const SymbolInfo *MachoParser::find_symbol(std::string_view name) const
	{
		for (const auto &sym: syms)
		{
			if (sym.name == name)
				return &sym;
		}
		return nullptr;
	}

	const std::vector<SegmentInfo> &MachoParser::segments() const
	{
		return segs;
	}

	const std::vector<SymbolInfo> &MachoParser::symbols() const
	{
		return syms;
	}

	const std::vector<IndirectSymbolInfo> &MachoParser::indirect_symbols() const
	{
		return indirect_syms;
	}

	bool MachoParser::has_symbol_table() const
	{
		return has_symtab;
	}

	bool MachoParser::has_dysym_table() const
	{
		return has_dysym_tab;
	}

	bool MachoParser::has_dyld_info_cmd() const
	{
		return has_dyld_info;
	}

	CpuType MachoParser::cpu_type() const
	{
		return cpu;
	}

	FileType MachoParser::file_type() const
	{
		return filetype;
	}

	std::uint32_t MachoParser::flags() const
	{
		return mach_flags;
	}

	void MachoParser::parse()
	{
		if (file.empty())
			return;

		std::size_t offset = 0;
		auto magic = read_at<std::uint32_t>(file, offset);
		offset += sizeof(std::uint32_t);

		/* header parsing */
		if (magic == static_cast<std::uint32_t>(Magic::FAT_MAGIC) ||
		    magic == static_cast<std::uint32_t>(Magic::FAT_CIGAM))
		{
			is_fat = true;
			swap_bytes = (magic == static_cast<std::uint32_t>(Magic::FAT_CIGAM));

			const auto nfat_arch = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			offset += sizeof(std::uint32_t);
			for (std::uint32_t i = 0; i < nfat_arch; i++)
			{
				FatArch arch = {};
				arch.cputype = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
				offset += sizeof(std::uint32_t);
				arch.cpusubtype = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
				offset += sizeof(std::uint32_t);
				arch.offset = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
				offset += sizeof(std::uint32_t);
				arch.size = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
				offset += sizeof(std::uint32_t);
				arch.align = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
				offset += sizeof(std::uint32_t);

				fat_archs.push_back(arch);
			}

			if (!fat_archs.empty())
			{
				offset = fat_archs[0].offset;
				magic = read_at<std::uint32_t>(file, offset);
				offset += sizeof(std::uint32_t);
			}
		}

		swap_bytes = false;
		switch (magic)
		{
			case static_cast<std::uint32_t>(Magic::MH_MAGIC):
				is_64bit = false;
				is_valid = true;
				break;
			case static_cast<std::uint32_t>(Magic::MH_CIGAM):
				is_64bit = false;
				swap_bytes = true;
				is_valid = true;
				break;
			case static_cast<std::uint32_t>(Magic::MH_MAGIC_64):
				is_64bit = true;
				is_valid = true;
				break;
			case static_cast<std::uint32_t>(Magic::MH_CIGAM_64):
				is_64bit = true;
				swap_bytes = true;
				is_valid = true;
				break;
			default:
				return;
		}

		if (is_64bit)
		{
			cpu = static_cast<CpuType>(read_at_swapped<std::uint32_t>(file, offset, swap_bytes));
			offset += sizeof(std::uint32_t);

			offset += sizeof(std::uint32_t); /* skip cpu subtype */

			filetype = static_cast<FileType>(read_at_swapped<std::uint32_t>(file, offset, swap_bytes));
			offset += sizeof(std::uint32_t);

			num_cmds = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			offset += sizeof(std::uint32_t);

			/****/
			[[maybe_unused]]
					auto sizeofcmds = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			/****/
			offset += sizeof(std::uint32_t);

			mach_flags = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			offset += sizeof(std::uint32_t);

			/* skip reserved field in 64-bit header */
			offset += sizeof(std::uint32_t);
		}
		else
		{
			cpu = static_cast<CpuType>(read_at_swapped<std::uint32_t>(file, offset, swap_bytes));
			offset += sizeof(std::uint32_t);

			/* skip CPU subtype */
			offset += sizeof(std::uint32_t);

			filetype = static_cast<FileType>(read_at_swapped<std::uint32_t>(file, offset, swap_bytes));
			offset += sizeof(std::uint32_t);

			num_cmds = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			offset += sizeof(std::uint32_t);

			/****/
			[[maybe_unused]]
					auto sizeofcmds = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			/****/
			offset += sizeof(std::uint32_t);

			mach_flags = read_at_swapped<std::uint32_t>(file, offset, swap_bytes);
			offset += sizeof(std::uint32_t);
		}

		/* LC parsing (load command) */
		std::size_t cmd_offset = offset;
		for (std::uint32_t i = 0; i < num_cmds; i++)
		{
			std::size_t cmd_start = cmd_offset;
			auto cmd = static_cast<LoadCommandType>(
				read_at_swapped<std::uint32_t>(file, cmd_offset, swap_bytes)
			);
			cmd_offset += sizeof(std::uint32_t);
			auto cmdsize = read_at_swapped<std::uint32_t>(file, cmd_offset, swap_bytes);
			cmd_offset += sizeof(std::uint32_t);
			switch (cmd)
			{
				case LoadCommandType::SEGMENT:
				{
					std::size_t seg_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					seg_offset += 2 * sizeof(std::uint32_t);

					SegmentInfo segment = {};
					segment.name = read_string(file, seg_offset, 16);
					seg_offset += 16; /* segname[16] */

					segment.vmaddr = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.vmsize = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.fileoff = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.filesize = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.maxprot = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.initprot = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					auto nsects = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.flags = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					/* read sections */
					for (std::uint32_t j = 0; j < nsects; j++)
					{
						SectionInfo section = {};

						section.sectname = read_string(file, seg_offset, 16);
						seg_offset += 16; /* sectname[16] */

						section.segname = read_string(file, seg_offset, 16);
						seg_offset += 16; /* segname[16] */

						section.addr = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.size = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.offset = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.align = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reloff = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.nreloc = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.flags = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reserved1 = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reserved2 = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						/* read section data if it exists in file */
						if (section.offset > 0 && section.size > 0 &&
						    (section.flags & static_cast<std::uint32_t>(SectionType::ZEROFILL)) == 0)
						{
							section.data.resize(section.size);
							std::memcpy(section.data.data(), file.data() + section.offset, section.size);
						}

						/* read relocations if they exist */
						if (section.reloff > 0 && section.nreloc > 0)
						{
							for (std::uint32_t k = 0; k < section.nreloc; k++)
							{
								std::size_t reloc_offset = section.reloff + k * sizeof(RelocationInfo);

								RelocationInfo reloc = {};
								reloc.r_address = read_at_swapped<std::int32_t>(file, reloc_offset, swap_bytes);
								reloc_offset += sizeof(std::int32_t);

								auto r_info = read_at<std::uint32_t>(file, reloc_offset);
								if (swap_bytes)
									r_info = swap_uint32(r_info);

								reloc.r_symbolnum = (r_info >> 8) & 0xFFFFFF;
								reloc.r_pcrel = (r_info >> 7) & 0x1;
								reloc.r_length = (r_info >> 5) & 0x3;
								reloc.r_extern = (r_info >> 4) & 0x1;
								reloc.r_type = r_info & 0xF;

								section.relocations.push_back(reloc);
							}
						}

						segment.sections.push_back(section);
					}

					segs.push_back(segment);
					break;
				}

				case LoadCommandType::SEGMENT_64:
				{
					std::size_t seg_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					seg_offset += 2 * sizeof(std::uint32_t);

					SegmentInfo segment = {};
					segment.name = read_string(file, seg_offset, 16);
					seg_offset += 16; /* segname[16] */

					segment.vmaddr = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint64_t);

					segment.vmsize = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint64_t);

					segment.fileoff = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint64_t);

					segment.filesize = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint64_t);

					segment.maxprot = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.initprot = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					auto nsects = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					segment.flags = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
					seg_offset += sizeof(std::uint32_t);

					/* read sections */
					for (std::uint32_t j = 0; j < nsects; j++)
					{
						SectionInfo section = {};

						section.sectname = read_string(file, seg_offset, 16);
						seg_offset += 16; /* sectname[16] */

						section.segname = read_string(file, seg_offset, 16);
						seg_offset += 16; /* segname[16] */

						section.addr = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint64_t);

						section.size = read_at_swapped<std::uint64_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint64_t);

						section.offset = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.align = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reloff = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.nreloc = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.flags = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reserved1 = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reserved2 = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						section.reserved3 = read_at_swapped<std::uint32_t>(file, seg_offset, swap_bytes);
						seg_offset += sizeof(std::uint32_t);

						/* read section data if it exists in file */
						if (section.offset > 0 && section.size > 0 &&
						    (section.flags & static_cast<std::uint32_t>(SectionType::ZEROFILL)) == 0)
						{
							section.data.resize(section.size);
							std::memcpy(section.data.data(), file.data() + section.offset, section.size);
						}

						/* read relocations if they exist */
						if (section.reloff > 0 && section.nreloc > 0)
						{
							for (std::uint32_t k = 0; k < section.nreloc; k++)
							{
								std::size_t reloc_offset = section.reloff + k * sizeof(RelocationInfo);

								RelocationInfo reloc = {};
								reloc.r_address = read_at_swapped<std::int32_t>(file, reloc_offset, swap_bytes);
								reloc_offset += sizeof(std::int32_t);

								auto r_info = read_at<std::uint32_t>(file, reloc_offset);
								if (swap_bytes)
									r_info = swap_uint32(r_info);

								reloc.r_symbolnum = (r_info >> 8) & 0xFFFFFF;
								reloc.r_pcrel = (r_info >> 7) & 0x1;
								reloc.r_length = (r_info >> 5) & 0x3;
								reloc.r_extern = (r_info >> 4) & 0x1;
								reloc.r_type = r_info & 0xF;

								section.relocations.push_back(reloc);
							}
						}

						segment.sections.push_back(section);
					}

					segs.push_back(segment);
					break;
				}

				case LoadCommandType::SYMTAB:
				{
					has_symtab = true;
					std::size_t symtab_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					symtab_offset += 2 * sizeof(std::uint32_t);

					symtab_cmd.symoff = read_at_swapped<std::uint32_t>(file, symtab_offset, swap_bytes);
					symtab_offset += sizeof(std::uint32_t);

					symtab_cmd.nsyms = read_at_swapped<std::uint32_t>(file, symtab_offset, swap_bytes);
					symtab_offset += sizeof(std::uint32_t);

					symtab_cmd.stroff = read_at_swapped<std::uint32_t>(file, symtab_offset, swap_bytes);
					symtab_offset += sizeof(std::uint32_t);

					symtab_cmd.strsize = read_at_swapped<std::uint32_t>(file, symtab_offset, swap_bytes);
					symtab_offset += sizeof(std::uint32_t);

					/* read string table */
					std::vector<char> string_table(symtab_cmd.strsize);
					std::memcpy(string_table.data(), file.data() + symtab_cmd.stroff, symtab_cmd.strsize);

					/* read symbol table */
					for (std::uint32_t j = 0; j < symtab_cmd.nsyms; j++)
					{
						SymbolInfo sym_info = {};
						std::size_t sym_offset = symtab_cmd.symoff + j * (is_64bit ? sizeof(Nlist64) : sizeof(Nlist32));

						if (is_64bit)
						{
							auto n_strx = read_at_swapped<std::uint32_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint32_t);

							auto n_type = read_at<std::uint8_t>(file, sym_offset);
							sym_offset += sizeof(std::uint8_t);

							auto n_sect = read_at<std::uint8_t>(file, sym_offset);
							sym_offset += sizeof(std::uint8_t);

							auto n_desc = read_at_swapped<std::uint16_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint16_t);

							auto n_value = read_at_swapped<std::uint64_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint64_t);

							sym_info.value = n_value;
							sym_info.type = n_type;
							sym_info.sect = n_sect;
							sym_info.desc = n_desc;

							/* get symbol name from string table */
							if (n_strx < symtab_cmd.strsize)
								sym_info.name = string_table.data() + n_strx;
						}
						else
						{
							auto n_strx = read_at_swapped<std::uint32_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint32_t);

							auto n_type = read_at<std::uint8_t>(file, sym_offset);
							sym_offset += sizeof(std::uint8_t);

							auto n_sect = read_at<std::uint8_t>(file, sym_offset);
							sym_offset += sizeof(std::uint8_t);

							auto n_desc = read_at_swapped<std::uint16_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint16_t);

							auto n_value = read_at_swapped<std::uint32_t>(file, sym_offset, swap_bytes);
							sym_offset += sizeof(std::uint32_t);

							sym_info.value = n_value;
							sym_info.type = n_type;
							sym_info.sect = n_sect;
							sym_info.desc = n_desc;

							/* get symbol name from string table */
							if (n_strx < symtab_cmd.strsize)
								sym_info.name = string_table.data() + n_strx;
						}

						sym_info.is_extern = (sym_info.type & static_cast<std::uint8_t>(SymbolFlags::EXT)) != 0;
						sym_info.is_undefined = (sym_info.type & static_cast<std::uint8_t>(SymbolFlags::TYPE)) ==
						                        static_cast<std::uint8_t>(SymbolType::UNDF);

						/* handle common symbols; typically undefined with a size */
						sym_info.is_common = sym_info.is_undefined && sym_info.value > 0;
						sym_info.common_size = sym_info.is_common ? sym_info.value : 0;
						sym_info.common_align = sym_info.is_common ? (sym_info.desc >> 8) & 0x0F : 0;
						syms.push_back(sym_info);
					}
					break;
				}

				case LoadCommandType::DYSYMTAB:
				{
					has_dysym_tab = true;
					std::size_t dysymtab_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					dysymtab_offset += 2 * sizeof(std::uint32_t);

					dysymtab_cmd.ilocalsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nlocalsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.iextdefsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nextdefsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.iundefsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nundefsym = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.tocoff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.ntoc = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.modtaboff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nmodtab = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.extrefsymoff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nextrefsyms = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.indirectsymoff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nindirectsyms = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.extreloff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nextrel = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.locreloff = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					dysymtab_cmd.nlocrel = read_at_swapped<std::uint32_t>(file, dysymtab_offset, swap_bytes);
					dysymtab_offset += sizeof(std::uint32_t);

					/* read indirect symbol table if it exists */
					if (dysymtab_cmd.indirectsymoff > 0 && dysymtab_cmd.nindirectsyms > 0)
					{
						for (std::uint32_t j = 0; j < dysymtab_cmd.nindirectsyms; j++)
						{
							std::size_t indsym_offset = dysymtab_cmd.indirectsymoff + j * sizeof(std::uint32_t);
							auto sym_index = read_at_swapped<std::uint32_t>(file, indsym_offset, swap_bytes);

							IndirectSymbolInfo indirect_sym = {};
							indirect_sym.symbol_index = sym_index;

							/* special values */
							if (sym_index != 0x80000000 && sym_index != 0x40000000)
							{
								/* normal symbol; get name from symbol table */
								if (sym_index < syms.size())
									indirect_sym.symbol_name = syms[sym_index].name;
							}

							indirect_syms.push_back(indirect_sym);
						}
					}
					break;
				}

				case LoadCommandType::DYLD_INFO:
				case LoadCommandType::DYLD_INFO_ONLY:
				{
					has_dyld_info = true;
					std::size_t dyld_info_offset = cmd_start;

					/* Skip cmd and cmdsize, already read */
					dyld_info_offset += 2 * sizeof(std::uint32_t);

					dyld_info.rebase_off = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.rebase_size = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.bind_off = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.bind_size = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.weak_bind_off = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.weak_bind_size = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.lazy_bind_off = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.lazy_bind_size = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.export_off = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);

					dyld_info.export_size = read_at_swapped<std::uint32_t>(file, dyld_info_offset, swap_bytes);
					dyld_info_offset += sizeof(std::uint32_t);
					break;
				}

				case LoadCommandType::LOAD_DYLIB:
				case LoadCommandType::ID_DYLIB:
				{
					std::size_t dylib_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					dylib_offset += 2 * sizeof(std::uint32_t);

					auto name_offset = read_at_swapped<std::uint32_t>(file, dylib_offset, swap_bytes);
					dylib_offset += sizeof(std::uint32_t);

					/* skip timestamp, current_version and compatibility_version */
					dylib_offset += 3 * sizeof(std::uint32_t);

					/* read dylib name */
					std::size_t name_pos = cmd_start + name_offset;
					std::string name = read_string(file, name_pos);
					if (cmd == LoadCommandType::LOAD_DYLIB)
						dylibs.push_back(name);
					break;
				}

				case LoadCommandType::UUID:
				{
					std::size_t uuid_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					uuid_offset += 2 * sizeof(std::uint32_t);

					/* read UUID */
					std::stringstream ss;
					ss << std::hex << std::setfill('0');
					for (auto j = 0; j < 16; j++)
					{
						auto byte = read_at<std::uint8_t>(file, uuid_offset + j);
						ss << std::setw(2) << static_cast<int>(byte);
						if (j == 3 || j == 5 || j == 7 || j == 9)
							ss << "-";
					}
					uuid = ss.str();
					break;
				}

				case LoadCommandType::MAIN:
				{
					std::size_t main_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					main_offset += 2 * sizeof(std::uint32_t);

					entry_point = read_at_swapped<std::uint64_t>(file, main_offset, swap_bytes);

					/* skip stacksize */
					/* main_offset += sizeof(std::uint64_t); */
					break;
				}

				case LoadCommandType::VERSION_MIN_MACOSX:
				case LoadCommandType::VERSION_MIN_IPHONEOS:
				case LoadCommandType::BUILD_VERSION:
				{
					std::size_t ver_offset = cmd_start;

					/* skip cmd and cmdsize, already read */
					ver_offset += 2 * sizeof(std::uint32_t);

					/* skip platform if it's `BUILD_VERSION` */
					if (cmd == LoadCommandType::BUILD_VERSION)
						ver_offset += sizeof(std::uint32_t);

					auto version = read_at_swapped<std::uint32_t>(file, ver_offset, swap_bytes);

					/* format version string */
					std::uint32_t x = (version >> 16) & 0xFFFF;
					std::uint32_t y = (version >> 8) & 0xFF;
					std::uint32_t z = version & 0xFF;

					std::stringstream ss;
					ss << x << "." << y;
					if (z > 0)
						ss << "." << z;

					min_version = ss.str();
					break;
				}
				default: ;
			}
			cmd_offset = cmd_start + cmdsize; /* move to next command */
		}
		if (has_dyld_info)
			parse_dynamic_linking();

		/*
		 * for whatever reason, clang doesn't seem to have a dedicated
		 * __DWARF section; however, the debug information is stored inside
		 * __TEXT segment instead.
		 */
		parse_chained_fixups();
		for (const auto& segment : segs)
		{
			for (const auto& section : segment.sections)
			{
				if (section.sectname.find("__debug_") == 0)
				{
					contains_dwarf = true;
					DwarfSectionType type = sectnamettype(section.sectname);
					if (type != DwarfSectionType::DEBUG_UNKNOWN)
					{
						DwarfSection& dwarf_section = dwarfinfo.sections[type];
						dwarf_section.offset = section.offset;
						dwarf_section.size = section.size;
						if (section.offset > 0 && section.size > 0)
							dwarf_section.data = section.data;
					}
				}
			}
		}

		for (const auto &segment: segs)
		{
			if (segment.name == "__DWARF")
			{
				contains_dwarf = true;

				for (const auto &section: segment.sections)
				{
					if (is_dwarf_section(section.sectname))
					{
						DwarfSectionType type = sectnamettype(section.sectname);
						DwarfSection &dwarf_section = dwarfinfo.sections[type];
						dwarf_section.offset = section.offset;
						dwarf_section.size = section.size;
						if (section.offset > 0 && section.size > 0)
							dwarf_section.data = section.data;
					}
				}
			}
		}
	}

	bool MachoParser::has_dynamic_linking() const
	{
		return dynlinking;
	}

	bool MachoParser::has_chained_fixups() const
	{
		return chainfixups;
	}

	const DynamicLinkingInfo &MachoParser::dynamic_linking_info() const
	{
		return dyldinfo;
	}

	bool MachoParser::has_dwarf() const
	{
		return contains_dwarf;
	}

	const DwarfInfo &MachoParser::dwarf_info() const
	{
		return dwarfinfo;
	}

	void MachoParser::parse_dynamic_linking()
	{
		dynlinking = true;
		dyldinfo.imported_libraries = dylibs;
		if (dyld_info.rebase_off > 0 && dyld_info.rebase_size > 0)
			parse_rebase_info();

		if (dyld_info.bind_off > 0 && dyld_info.bind_size > 0)
			parse_bind_info(dyld_info.bind_off, dyld_info.bind_size, dyldinfo.binds);

		if (dyld_info.weak_bind_off > 0 && dyld_info.weak_bind_size > 0)
			parse_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, dyldinfo.weak_binds);

		if (dyld_info.lazy_bind_off > 0 && dyld_info.lazy_bind_size > 0)
			parse_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, dyldinfo.lazy_binds);
	}

	void MachoParser::parse_rebase_info()
	{
		if (dyld_info.rebase_off == 0 || dyld_info.rebase_size == 0)
			return;

		std::size_t offset = dyld_info.rebase_off;
		const std::size_t end = offset + dyld_info.rebase_size;

		auto type = RebaseType::POINTER;
		std::uint8_t segment_index = 0;
		std::uint64_t segment_offset = 0;
		while (offset < end)
		{
			std::uint8_t opcode = file[offset++];
			std::uint8_t immediate = opcode & 0x0F;
			opcode = opcode & 0xF0;

			switch (static_cast<RebaseOpcode>(opcode))
			{
				case RebaseOpcode::DONE:
					return;

				case RebaseOpcode::SET_TYPE_IMM:
					type = static_cast<RebaseType>(immediate);
					break;

				case RebaseOpcode::SET_SEGMENT_AND_OFFSET_ULEB:
				{
					segment_index = immediate;
					segment_offset = read_uleb128(file.data(), offset);
					break;
				}

				case RebaseOpcode::ADD_ADDR_ULEB:
				{
					segment_offset += read_uleb128(file.data(), offset);
					break;
				}

				case RebaseOpcode::ADD_ADDR_IMM_SCALED:
				{
					segment_offset += immediate * (is_64bit ? 8 : 4);
					break;
				}

				case RebaseOpcode::DO_REBASE_IMM_TIMES:
				{
					for (std::uint8_t i = 0; i < immediate; i++)
					{
						RebaseInfo rebase;
						rebase.type = type;
						rebase.segment_index = segment_index;
						rebase.segment_offset = segment_offset;
						rebase.address = compute_addr(segs, segment_index, segment_offset);

						dyldinfo.rebases.push_back(rebase);

						segment_offset += (is_64bit ? 8 : 4);
					}
					break;
				}

				case RebaseOpcode::DO_REBASE_ULEB_TIMES:
				{
					const std::uint64_t count = read_uleb128(file.data(), offset);
					for (std::uint64_t i = 0; i < count; i++)
					{
						RebaseInfo rebase;
						rebase.type = type;
						rebase.segment_index = segment_index;
						rebase.segment_offset = segment_offset;
						rebase.address = compute_addr(segs, segment_index, segment_offset);

						dyldinfo.rebases.push_back(rebase);

						segment_offset += (is_64bit ? 8 : 4);
					}
					break;
				}

				case RebaseOpcode::DO_REBASE_ADD_ADDR_ULEB:
				{
					RebaseInfo rebase;
					rebase.type = type;
					rebase.segment_index = segment_index;
					rebase.segment_offset = segment_offset;
					rebase.address = compute_addr(segs, segment_index, segment_offset);

					dyldinfo.rebases.push_back(rebase);

					segment_offset += read_uleb128(file.data(), offset) + (is_64bit ? 8 : 4);
					break;
				}

				case RebaseOpcode::DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
				{
					const std::uint64_t count = read_uleb128(file.data(), offset);
					const std::uint64_t skip = read_uleb128(file.data(), offset);
					for (std::uint64_t i = 0; i < count; i++)
					{
						RebaseInfo rebase;
						rebase.type = type;
						rebase.segment_index = segment_index;
						rebase.segment_offset = segment_offset;
						rebase.address = compute_addr(segs, segment_index, segment_offset);

						dyldinfo.rebases.push_back(rebase);

						segment_offset += skip + (is_64bit ? 8 : 4);
					}
					break;
				}
			}
		}
	}

	void MachoParser::parse_bind_info(std::uint32_t offset_val, std::uint32_t size, std::vector<BindInfo> &binds)
	{
		if (offset_val == 0 || size == 0)
			return;

		std::size_t offset = offset_val;
		std::size_t end = offset + size;

		BindInfo current_bind = {};
		std::uint8_t segment_index = 0;
		std::uint64_t segment_offset = 0;
		while (offset < end)
		{
			std::uint8_t opcode = file[offset++];
			std::uint8_t immediate = opcode & 0x0F;
			opcode = opcode & 0xF0;

			switch (static_cast<BindOpcode>(opcode))
			{
				case BindOpcode::DONE:
					return;

				case BindOpcode::SET_DYLIB_ORDINAL_IMM:
					current_bind.library_ordinal = immediate;
					break;

				case BindOpcode::SET_DYLIB_ORDINAL_ULEB:
				{
					current_bind.library_ordinal = static_cast<std::int8_t>(read_uleb128(file.data(), offset));
					break;
				}

				case BindOpcode::SET_DYLIB_SPECIAL_IMM:
				{
					/* special cases for SELF, MAIN_EXECUTABLE, etc. */
					if (immediate == 0)
						current_bind.library_ordinal = 0;
					else /* sign extend the imm */
						current_bind.library_ordinal = static_cast<std::int8_t>(0xF0 | immediate);
					break;
				}

				case BindOpcode::SET_SYMBOL_TRAILING_FLAGS_IMM:
				{
					current_bind.symbol_flags = immediate;
					std::string symbol_name;
					char c;
					while ((c = file[offset++]) != '\0')
					{
						symbol_name.push_back(c);
					}
					current_bind.symbol_name = symbol_name;
					break;
				}

				case BindOpcode::SET_TYPE_IMM:
					current_bind.type = static_cast<BindType>(immediate);
					break;

				case BindOpcode::SET_ADDEND_SLEB:
				{
					current_bind.addend = read_sleb128(file.data(), offset);
					break;
				}

				case BindOpcode::SET_SEGMENT_AND_OFFSET_ULEB:
				{
					segment_index = immediate;
					segment_offset = read_uleb128(file.data(), offset);
					break;
				}

				case BindOpcode::ADD_ADDR_ULEB:
				{
					segment_offset += read_uleb128(file.data(), offset);
					break;
				}

				case BindOpcode::DO_BIND:
				{
					BindInfo bind = current_bind;
					bind.segment_index = segment_index;
					bind.segment_offset = segment_offset;
					bind.address = compute_addr(segs, segment_index, segment_offset);

					binds.push_back(bind);

					segment_offset += (is_64bit ? 8 : 4);
					break;
				}

				case BindOpcode::DO_BIND_ADD_ADDR_ULEB:
				{
					BindInfo bind = current_bind;
					bind.segment_index = segment_index;
					bind.segment_offset = segment_offset;
					bind.address = compute_addr(segs, segment_index, segment_offset);

					binds.push_back(bind);

					segment_offset += read_uleb128(file.data(), offset) + (is_64bit ? 8 : 4);
					break;
				}

				case BindOpcode::DO_BIND_ADD_ADDR_IMM_SCALED:
				{
					BindInfo bind = current_bind;
					bind.segment_index = segment_index;
					bind.segment_offset = segment_offset;
					bind.address = compute_addr(segs, segment_index, segment_offset);

					binds.push_back(bind);

					segment_offset += immediate * (is_64bit ? 8 : 4) + (is_64bit ? 8 : 4);
					break;
				}

				case BindOpcode::DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
				{
					std::uint64_t count = read_uleb128(file.data(), offset);
					std::uint64_t skip = read_uleb128(file.data(), offset);

					for (std::uint64_t i = 0; i < count; i++)
					{
						BindInfo bind = current_bind;
						bind.segment_index = segment_index;
						bind.segment_offset = segment_offset;
						bind.address = compute_addr(segs, segment_index, segment_offset);

						binds.push_back(bind);

						segment_offset += skip + (is_64bit ? 8 : 4);
					}
					break;
				}
			}
		}
	}

	void MachoParser::parse_chained_fixups()
	{
		/* try to find `LC_DYLD_CHAINED_FIXUPS` command */
		std::size_t cmd_offset = is_64bit ? sizeof(Header64) : sizeof(Header32);
		for (std::uint32_t i = 0; i < num_cmds; i++)
		{
			std::size_t cmd_start = cmd_offset;
			auto cmd = static_cast<LoadCommandType>(
				read_at_swapped<std::uint32_t>(file, cmd_offset, swap_bytes)
			);
			cmd_offset += sizeof(std::uint32_t);

			auto cmdsize = read_at_swapped<std::uint32_t>(file, cmd_offset, swap_bytes);
			cmd_offset += sizeof(std::uint32_t);

			if (cmd == LoadCommandType::DYLD_CHAINED_FIXUPS)
			{
				std::size_t fixups_offset = cmd_start + 2 * sizeof(std::uint32_t);

				ChainedFixupsHeader &header = dyldinfo.chained_header;
				header.fixups_version = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.starts_offset = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.imports_offset = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.symbols_offset = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.imports_count = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.imports_format = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);
				fixups_offset += sizeof(std::uint32_t);

				header.symbols_format = read_at_swapped<std::uint32_t>(file, fixups_offset, swap_bytes);

				std::size_t fixups_base = cmd_start;
				if (header.starts_offset > 0)
				{
					std::size_t starts_offset = fixups_base + header.starts_offset;
					ChainedStartsInImage &starts = dyldinfo.chained_starts;

					starts.seg_count = read_at_swapped<std::uint32_t>(file, starts_offset, swap_bytes);
					starts_offset += sizeof(std::uint32_t);
					starts.seg_info_offset.resize(starts.seg_count);
					for (std::uint32_t j = 0; j < starts.seg_count; j++)
					{
						starts.seg_info_offset[j] = read_at_swapped<std::uint32_t>(file, starts_offset, swap_bytes);
						starts_offset += sizeof(std::uint32_t);
					}

					/* parse each segment's starts */
					starts.segments.resize(starts.seg_count);
					for (std::uint32_t j = 0; j < starts.seg_count; j++)
					{
						if (starts.seg_info_offset[j] == 0)
							continue;

						std::size_t seg_info_offset = fixups_base + header.starts_offset + starts.seg_info_offset[j];
						ChainedStartsInSegment &seg_starts = starts.segments[j];

						seg_starts.size = read_at_swapped<std::uint32_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint32_t);

						seg_starts.page_size = read_at_swapped<std::uint16_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint16_t);

						seg_starts.pointer_format = read_at_swapped<std::uint16_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint16_t);

						seg_starts.segment_offset = read_at_swapped<std::uint64_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint64_t);

						seg_starts.max_valid_pointer = read_at_swapped<
							std::uint32_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint32_t);

						seg_starts.page_count = read_at_swapped<std::uint16_t>(file, seg_info_offset, swap_bytes);
						seg_info_offset += sizeof(std::uint16_t);

						/* read page starts */
						seg_starts.page_starts.resize(seg_starts.page_count);
						for (std::uint16_t k = 0; k < seg_starts.page_count; k++)
						{
							seg_starts.page_starts[k] = read_at_swapped<std::uint16_t>(
								file, seg_info_offset, swap_bytes);
							seg_info_offset += sizeof(std::uint16_t);
						}
					}
				}

				/* parse imports and symbols */
				if (header.imports_offset > 0 && header.symbols_offset > 0 && header.imports_count > 0)
				{
					std::size_t symbols_offset = fixups_base + header.symbols_offset;
					for (std::uint32_t j = 0; j < header.imports_count; j++)
					{
						std::size_t import_offset = fixups_base + header.imports_offset +
						                            j * (header.imports_format == 1
							                                 ? sizeof(ChainedImport)
							                                 : header.imports_format == 2
								                                   ? sizeof(ChainedImportAddend)
								                                   : sizeof(ChainedImportAddend64));

						/* create binding info */
						BindInfo bind;
						bind.type = BindType::POINTER;
						std::uint32_t name_offset = 0;

						if (header.imports_format == 1)
						{
							ChainedImport import;
							std::memcpy(&import, file.data() + import_offset, sizeof(ChainedImport));
							if (swap_bytes)
							{
								std::uint32_t raw;
								std::memcpy(&raw, &import, sizeof(std::uint32_t));
								raw = swap_uint32(raw);

								import.lib_ordinal = (raw >> 24);
								import.weak_import = (raw >> 23) & 0x1;
								import.name_offset = raw & 0x7FFFFF;
							}

							bind.library_ordinal = import.lib_ordinal;
							bind.symbol_flags = import.weak_import
								                    ? static_cast<std::uint8_t>(BindSymbolFlags::WEAK_IMPORT)
								                    : 0;
							bind.addend = 0;
							name_offset = import.name_offset;
						}
						else if (header.imports_format == 2)
						{
							ChainedImportAddend import;
							std::memcpy(&import, file.data() + import_offset, sizeof(ChainedImportAddend));
							if (swap_bytes)
							{
								std::uint32_t raw;
								std::memcpy(&raw, &import, sizeof(std::uint32_t));
								raw = swap_uint32(raw);

								import.lib_ordinal = (raw >> 24);
								import.weak_import = (raw >> 23) & 0x1;
								import.name_offset = raw & 0x7FFFFF;
								import.addend = swap_uint32(import.addend);
							}

							bind.library_ordinal = import.lib_ordinal;
							bind.symbol_flags = import.weak_import
								                    ? static_cast<std::uint8_t>(BindSymbolFlags::WEAK_IMPORT)
								                    : 0;
							bind.addend = import.addend;
							name_offset = import.name_offset;
						}
						else
						{
							ChainedImportAddend64 import;
							std::memcpy(&import, file.data() + import_offset, sizeof(ChainedImportAddend64));
							if (swap_bytes)
							{
								std::uint64_t raw;
								std::memcpy(&raw, &import, sizeof(std::uint64_t));
								raw = swap_uint64(raw);

								import.lib_ordinal = (raw >> 48);
								import.weak_import = (raw >> 47) & 0x1;
								import.reserved = (raw >> 32) & 0x7FFF;
								import.name_offset = raw & 0xFFFFFFFF;
								import.addend = swap_uint64(import.addend);
							}

							bind.library_ordinal = import.lib_ordinal;
							bind.symbol_flags = import.weak_import
								                    ? static_cast<std::uint8_t>(BindSymbolFlags::WEAK_IMPORT)
								                    : 0;
							bind.addend = import.addend;
							name_offset = import.name_offset;
						}

						std::string symbol_name = read_string(file, symbols_offset + name_offset);
						bind.symbol_name = symbol_name;

						/* no address yet since chain entries need to be found */
						/* to that reference this import */
						dyldinfo.chained_binds.push_back(bind);
					}
				}

				dynlinking = true;
				chainfixups = true;
				dyldinfo.has_chained_fixups = true;
				break;
			}

			cmd_offset = cmd_start + cmdsize;
		}
	}

	void MachoParser::parse_lazy_bind_info()
	{
		if (dyld_info.lazy_bind_off > 0 && dyld_info.lazy_bind_size > 0)
			parse_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, dyldinfo.lazy_binds);
	}

	void MachoParser::parse_weak_bind_info()
	{
		if (dyld_info.weak_bind_off > 0 && dyld_info.weak_bind_size > 0)
			parse_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, dyldinfo.weak_binds);
	}

	const DwarfSection *MachoParser::dwarf_section(DwarfSectionType type) const
	{
		const auto it = dwarfinfo.sections.find(type);
		if (it != dwarfinfo.sections.end())
			return &it->second;
		return nullptr;
	}
}
