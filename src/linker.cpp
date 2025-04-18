/* this file is a part of Knit linker project; see LICENSE for more info */

#include <algorithm>
#include <iostream>
#include <knit/linker.hpp>

namespace knt
{
	MachoLinker::MachoLinker() : target_cpu(CpuType::ARM64), is_64bit(true) {}

	void MachoLinker::set_target_cpu(CpuType cpu)
	{
		target_cpu = cpu;
		is_64bit = (cpu == CpuType::X86_64 ||
		            cpu == CpuType::ARM64 ||
		            cpu == CpuType::POWERPC64);
	}

	bool MachoLinker::add_input(std::string_view path)
	{
		const auto obj = std::make_shared<ObjectFile>(path);
		if (!obj->parser.is_macho())
		{
			std::cerr << "error: " << path << " is not a valid Mach-O file" << std::endl;
			return false;
		}

		if (obj->parser.file_type() != FileType::OBJECT)
		{
			std::cerr << "error: " << path << " is not an object file" << std::endl;
			return false;
		}

		if (input_files.empty())
		{
			target_cpu = obj->parser.cpu_type();
			is_64bit = (target_cpu == CpuType::X86_64 ||
			            target_cpu == CpuType::ARM64 ||
			            target_cpu == CpuType::POWERPC64);
		}
		else
		{
			if (obj->parser.cpu_type() != target_cpu)
			{
				std::cerr << "error: " << path << " has incompatible architecture" << std::endl;
				return false;
			}
		}

		input_files.push_back(obj);
		return true;
	}

	bool MachoLinker::proc()
	{
		if (input_files.empty())
		{
			std::cerr << "error: no input files" << std::endl;
			return false;
		}

		/* first pass: collect all symbols */
		for (auto &file: input_files)
		{
			for (const auto &symbols = file->parser.symbols();
			     const auto &sym: symbols)
			{
				if (sym.is_extern)
				{
					if (!sym.is_undefined)
					{
						/* defined */
						auto name = sym.name;
						if (auto it = defined_symbols.find(name);
							it != defined_symbols.end())
						{
							auto &existing = it->second;
							if (existing.is_common && sym.is_common)
							{
								/* both symbols are common; take the larger one */
								if (sym.common_size > existing.common_size)
								{
									existing.symbol = &sym;
									existing.file = file.get();
									existing.common_size = sym.common_size;
									existing.common_align = std::max(existing.common_align, sym.common_align);
								}
							}
							if (existing.is_common && !sym.is_common)
							{
								/* defined symbol overrides common symbol */
								existing.symbol = &sym;
								existing.file = file.get();
								existing.is_common = false;
								existing.common_size = 0;
								existing.common_align = 0;
							}
							if (existing.is_weak && !sym.is_weak)
							{
								/* strong overrides weak */
								existing.symbol = &sym;
								existing.file = file.get();
								existing.is_weak = false;
							}
							if (!existing.is_weak && !sym.is_weak)
							{
								/* error if there are multiple same strong symbols */
								std::cerr << "error: symbol '" << name << "' multiply defined" << std::endl;
								return false;
							}
						}
						else
						{
							/* make a new symbol */
							SymbolResolution res;
							res.symbol = &sym;
							res.file = file.get();
							res.is_weak = (sym.desc & 0x80) != 0; /* N_WEAK_DEF*/
							res.is_common = sym.is_common;
							res.common_size = sym.common_size;
							res.common_align = sym.common_align;
							defined_symbols[name] = res;
						}
					}
				}
			}
		}

		/* check for any undefined symbols */
		for (const auto &file: input_files)
		{
			for (const auto &symbols = file->parser.symbols();
			     const auto &sym: symbols)
			{
				if (sym.is_extern && sym.is_undefined)
				{
					if (auto name = sym.name;
						!defined_symbols.contains(name))
					{
						std::cerr << "error: undefined symbol: " << name << std::endl;
						return false;
					}
				}
			}
		}

		return true;
	}

	bool MachoLinker::link(std::string_view out_path)
	{
		if (!proc())
		{
			return false;
		}

		/* merge */
		std::map<std::pair<std::string, std::string>, SectionInfo2> merged_sections;
		for (auto &file: input_files)
		{
			const auto &segments = file->parser.segments();
			size_t sect_idx = 0;

			for (const auto &seg: segments)
			{
				for (const auto &sect: seg.sections)
				{
					auto key = std::make_pair(seg.name, sect.sectname);

					if (merged_sections.find(key) == merged_sections.end())
					{
						SectionInfo2 info;
						info.segname = seg.name;
						info.sectname = sect.sectname;
						info.align = sect.align;
						info.flags = sect.flags;
						merged_sections[key] = info;
					}

					/* add crap here bla bla bla */
					SectionInfo2 &output_sect = merged_sections[key];
					output_sect.align = std::max(output_sect.align, sect.align);
					uint64_t offset = output_sect.size;
					uint32_t align_mask = (1 << output_sect.align) - 1;
					if (offset & align_mask)
						offset = (offset + align_mask) & ~align_mask;

					SectionInfo2::SourceSection source = {};
					source.file = file.get();
					source.index = sect_idx;
					source.offset = offset;
					output_sect.sources.push_back(source);

					/* update state & output size */
					output_sect.size = offset + sect.size;
					sect_idx++;
				}
			}
		}

		std::vector<SectionInfo2> output_sections;
		output_sections.reserve(merged_sections.size());
		for (auto &pair: merged_sections)
			output_sections.push_back(pair.second);

		/* default base addr; to be used later for calculating the correct _main in __TEXT */
		uint64_t base_addr = 0x100000000;
		uint64_t current_addr = base_addr;

		for (auto &sect: output_sections)
		{
			/* align */
			if (uint32_t align_mask = (1 << sect.align) - 1;
				current_addr & align_mask)
				current_addr = (current_addr + align_mask) & ~align_mask;

			sect.addr = current_addr;
			current_addr += sect.size;

			sect.data.resize(sect.size);
			for (const auto &[file, index, offset]: sect.sources)
			{
				const auto &segments = file->parser.segments();
				size_t sect_idx = 0;
				auto found = false;
				for (const auto &seg: segments)
				{
					for (const auto &section: seg.sections)
					{
						if (sect_idx == index)
						{
							found = true;
							if ((section.flags & static_cast<uint32_t>(SectionType::ZEROFILL)) == 0 && !section.data.
							    empty())
							{
								std::memcpy(sect.data.data() + offset, section.data.data(), section.size);
							}
							break;
						}
						sect_idx++;
					}
					if (found)
						break;
				}
			}
		}

		std::map<std::string, uint64_t> symbol_addresses;
		for (auto &[fst, snd]: defined_symbols)
		{
			const std::string &name = fst;
			SymbolResolution &sym_res = snd;
			const SymbolInfo &sym = *sym_res.symbol;

			if (sym.sect > 0)
			{
				if (uint64_t sym_addr = get_symbol_address(sym_res.file, sym);
					sym_addr != 0)
				{
					symbol_addresses[name] = sym_addr;
				}
			}
		}

		apply_relocations(output_sections, symbol_addresses);
		return write_output_file(out_path, output_sections, symbol_addresses);
	}

	uint64_t MachoLinker::get_symbol_address(ObjectFile *file, const SymbolInfo &sym)
	{
		if (sym.sect == 0)
			return 0; /* undefined symbol */

		const auto &segments = file->parser.segments();
		std::size_t sect_idx = 0;
		const std::size_t target_sect_idx = sym.sect - 1;
		for (const auto &seg: segments)
		{
			for (size_t i = 0; i < seg.sections.size(); i++)
			{
				if (sect_idx == target_sect_idx)
				{
					const auto &in_sect = seg.sections[i];
					for (const auto &out_sect: output_sections)
					{
						if (out_sect.segname == seg.name && out_sect.sectname == in_sect.sectname)
						{
							for (const auto &source: out_sect.sources)
							{
								if (source.file == file && source.index == sect_idx)
									return out_sect.addr + source.offset + sym.value - in_sect.addr;
							}
						}
					}
					return 0;
				}
				sect_idx++;
			}
		}

		return 0; /* not found */
	}

	void MachoLinker::apply_relocations(std::vector<SectionInfo2> &sections,
	                                    const std::map<std::string, uint64_t> &symbol_addresses)
	{
		for (auto &out_sect: sections)
		{
			for (const auto &source: out_sect.sources)
			{
				const auto &segments = source.file->parser.segments();
				size_t sect_idx = 0;
				bool found = false;

				for (const auto &seg: segments)
				{
					for (const auto &in_sect: seg.sections)
					{
						if (sect_idx == source.index)
						{
							found = true;
							for (const auto &reloc: in_sect.relocations)
								apply_relocation(out_sect, source, in_sect, reloc, symbol_addresses, source.file);
							break;
						}
						sect_idx++;
					}
					if (found)
						break;
				}
			}
		}
	}

	void MachoLinker::apply_relocation(SectionInfo2 &sect, const SectionInfo2::SourceSection &source,
	                                   const SectionInfo &in_sect, const RelocationInfo &reloc,
	                                   const std::map<std::string, uint64_t> &symbol_addresses,
	                                   const ObjectFile *file)
	{
		std::uint64_t address = source.offset + reloc.r_address;
		std::uint8_t *data_ptr = sect.data.data() + address;
		if (reloc.r_extern) /* symbol-based */
		{
			/* external symbol (with `extern` keyword); reference a symbol */
			const auto &symbols = file->parser.symbols();
			if (reloc.r_symbolnum < symbols.size())
			{
				const auto &sym = symbols[reloc.r_symbolnum];
				if (auto it = symbol_addresses.find(sym.name);
					it != symbol_addresses.end())
				{
					const uint64_t target_addr = it->second;
					if (target_cpu == CpuType::X86_64)
						apply_x86_64_relocation(sect, address, data_ptr, reloc, target_addr);
					else if (target_cpu == CpuType::ARM64)
						apply_arm64_relocation(sect, address, data_ptr, reloc, target_addr);
				}
			}
		}
		else
		{
			if (std::size_t sect_num = reloc.r_symbolnum;
				sect_num > 0)
			{
				const auto &segments = file->parser.segments();
				size_t current_sect = 0;
				for (const auto &seg: segments)
				{
					for (size_t i = 0; i < seg.sections.size(); i++)
					{
						current_sect++;
						if (current_sect == sect_num)
						{
							const auto &target_sect = seg.sections[i];
							for (const auto &out_sect: output_sections)
							{
								if (out_sect.segname == seg.name && out_sect.sectname == target_sect.sectname)
								{
									uint64_t target_addr = out_sect.addr;
									if (target_cpu == CpuType::X86_64)
										apply_x86_64_section_relocation(sect, address, data_ptr, reloc, target_addr);
									else if (target_cpu == CpuType::ARM64)
										apply_arm64_section_relocation(sect, address, data_ptr, reloc, target_addr);
									break;
								}
							}
							break;
						}
					}
				}
			}
		}
	}

	void MachoLinker::apply_x86_64_relocation(const SectionInfo2 &sect, const uint64_t address, uint8_t *data_ptr,
	                                          const RelocationInfo &reloc, const uint64_t target_addr)
	{
		switch (static_cast<RelocationType>(reloc.r_type))
		{
			case RelocationType::X86_64_RELOC_UNSIGNED:
			{
				uint64_t value;
				memcpy(&value, data_ptr, 8);
				value = target_addr;
				memcpy(data_ptr, &value, 8);
				break;
			}
			case RelocationType::X86_64_RELOC_SIGNED:
			case RelocationType::X86_64_RELOC_BRANCH:
			{
				/* PC-relative addressing; 32-bit displacement) */
				int32_t disp;
				memcpy(&disp, data_ptr, 4);

				/* PC is address of next instruction; + 4 because each AArch64 instruction is 4 bytes long */
				disp = static_cast<int32_t>(target_addr - (sect.addr + address + 4));

				memcpy(data_ptr, &disp, 4);
				break;
			}
			case RelocationType::X86_64_RELOC_GOT_LOAD:
			{
				/* TODO: impl GOT handling */
				int32_t disp;
				memcpy(&disp, data_ptr, 4);
				disp = static_cast<int32_t>(target_addr - (sect.addr + address + 4));
				memcpy(data_ptr, &disp, 4);
				break;
			}
			case RelocationType::X86_64_RELOC_SIGNED_1:
			{
				/* same thing like SIGNED but with -1 addend */
				int32_t disp;
				memcpy(&disp, data_ptr, 4);

				disp = static_cast<int32_t>(target_addr - (sect.addr + address + 4) - 1);

				memcpy(data_ptr, &disp, 4);
				break;
			}
			case RelocationType::X86_64_RELOC_SIGNED_2:
			{
				/* same thing like SIGNED but with -2 addend */
				int32_t disp;
				memcpy(&disp, data_ptr, 4);

				disp = static_cast<int32_t>(target_addr - (sect.addr + address + 4) - 2);

				memcpy(data_ptr, &disp, 4);
				break;
			}
			case RelocationType::X86_64_RELOC_SIGNED_4:
			{
				/* same thing like SIGNED but with -4 addend */
				int32_t disp;
				memcpy(&disp, data_ptr, 4);

				disp = static_cast<int32_t>(target_addr - (sect.addr + address + 4) - 4);

				memcpy(data_ptr, &disp, 4);
				break;
			}
			default:
				std::cerr << "<warning>: unsupported x86_64 relocation type: " << static_cast<int>(reloc.r_type) <<
						std::endl;
				break;
		}
	}

	void MachoLinker::apply_x86_64_section_relocation(SectionInfo2 &sect, uint64_t address, uint8_t *data_ptr,
	                                                  const RelocationInfo &reloc, uint64_t target_addr)
	{
		apply_x86_64_relocation(sect, address, data_ptr, reloc, target_addr);
	}

	void MachoLinker::apply_arm64_relocation(const SectionInfo2 &sect, uint64_t address, uint8_t *data_ptr,
	                                         const RelocationInfo &reloc, uint64_t target_addr)
	{
		switch (static_cast<RelocationType>(reloc.r_type))
		{
			case RelocationType::ARM64_RELOC_UNSIGNED:
			{
				uint64_t value;
				memcpy(&value, data_ptr, 8);
				value = target_addr;
				memcpy(data_ptr, &value, 8);
				break;
			}
			case RelocationType::ARM64_RELOC_BRANCH26:
			{
				uint32_t insn;
				memcpy(&insn, data_ptr, 4);
				insn &= ~0x03FFFFFF;
				int64_t offset = target_addr - (sect.addr + address);
				offset >>= 2;
				if (offset < -0x2000000 || offset > 0x1FFFFFF)
				{
					std::cerr << "error: branch target out of range" << std::endl;
				}
				else
				{
					insn |= (offset & 0x03FFFFFF);
					memcpy(data_ptr, &insn, 4);
				}
				break;
			}
			case RelocationType::ARM64_RELOC_PAGE21:
			{
				uint32_t insn;
				memcpy(&insn, data_ptr, 4);
				uint64_t pc = (sect.addr + address) & ~0xFFF;

				uint64_t target_page = target_addr & ~0xFFF;
				auto page_diff = static_cast<int64_t>(target_page - pc);
				uint32_t immlo = (page_diff & 0x3) << 29;
				uint32_t immhi = ((page_diff & 0x1FFFFC) >> 2) << 5;
				insn &= ~(0x60000000);
				insn &= ~(0x7FFFF << 5);
				insn |= immlo;
				insn |= immhi;
				memcpy(data_ptr, &insn, 4);
				break;
			}
			case RelocationType::ARM64_RELOC_PAGEOFF12:
			{
				uint32_t insn;
				memcpy(&insn, data_ptr, 4);
				uint32_t offset = target_addr & 0xFFF;
				if ((insn & 0x3B000000) == 0x39000000)
				{
					uint32_t size = (insn >> 30) & 0x3;
					insn &= ~(0xFFF << 10);
					uint32_t scaled_offset = offset >> size;
					insn |= (scaled_offset & 0xFFF) << 10;
				}
				else
				{
					insn &= ~(0xFFF << 10);
					insn |= (offset & 0xFFF) << 10;
				}

				memcpy(data_ptr, &insn, 4);
				break;
			}
			default:
				std::cerr << "<warning>: unsupported ARM64 relocation type: " << static_cast<int>(reloc.r_type) <<
						std::endl;
				break;
		}
	}

	void MachoLinker::apply_arm64_section_relocation(SectionInfo2 &sect, uint64_t address, uint8_t *data_ptr,
	                                                 const RelocationInfo &reloc, uint64_t target_addr)
	{
		apply_arm64_relocation(sect, address, data_ptr, reloc, target_addr);
	}

	bool MachoLinker::write_output_file(std::string_view path, const std::vector<SectionInfo2> &sections,
	                                    const std::map<std::string, uint64_t> &symbol_addresses)
	{
		std::ofstream file(path.data(), std::ios::binary);
		if (!file)
		{
			std::cerr << "error: cannot open output file " << path << std::endl;
			return false;
		}

		std::vector<std::pair<std::string, std::vector<const SectionInfo2 *> > > segments;
		std::map<std::string, std::vector<const SectionInfo2 *> > segment_map;

		for (const auto &sect: sections)
			segment_map[sect.segname].push_back(&sect);

		segments.reserve(segment_map.size());
		for (auto &pair: segment_map)
			segments.emplace_back(pair);

		if (!segment_map.contains("__PAGEZERO"))
			segments.insert(segments.begin(), std::make_pair("__PAGEZERO", std::vector<const SectionInfo2 *>()));

		if (!segment_map.contains("__LINKEDIT"))
			segments.emplace_back("__LINKEDIT", std::vector<const SectionInfo2 *>());

		uint32_t ncmds = segments.size() + 2; /* segments + LC_SYMTAB + LC_MAIN */
		uint32_t sizeofcmds = 0;
		for (const auto &seg: segments)
		{
			if (is_64bit)
			{
				sizeofcmds += sizeof(SegmentCommand64);
				sizeofcmds += seg.second.size() * sizeof(Section64);
			}
			else
			{
				sizeofcmds += sizeof(SegmentCommand32);
				sizeofcmds += seg.second.size() * sizeof(Section32);
			}
		}

		sizeofcmds += sizeof(SymtabCommand);
		sizeofcmds += sizeof(EntryPointCommand);
		if (is_64bit)
		{
			Header64 header = {};
			memset(&header, 0, sizeof(header));
			header.magic = static_cast<uint32_t>(Magic::MH_MAGIC_64);
			header.cputype = static_cast<uint32_t>(target_cpu);
			header.cpusubtype = 0;
			header.filetype = static_cast<uint32_t>(FileType::EXECUTE);
			header.ncmds = ncmds;
			header.sizeofcmds = sizeofcmds;
			header.flags = 0;
			header.reserved = 0;

			file.write(reinterpret_cast<const char *>(&header), sizeof(header));
		}
		else
		{
			Header32 header = {};
			memset(&header, 0, sizeof(header));
			header.magic = static_cast<uint32_t>(Magic::MH_MAGIC);
			header.cputype = static_cast<uint32_t>(target_cpu);
			header.cpusubtype = 0;
			header.filetype = static_cast<uint32_t>(FileType::EXECUTE);
			header.ncmds = ncmds;
			header.sizeofcmds = sizeofcmds;
			header.flags = 0;

			file.write(reinterpret_cast<const char *>(&header), sizeof(header));
		}

		uint64_t file_offset = (is_64bit ? sizeof(Header64) : sizeof(Header32)) + sizeofcmds;
		for (const auto &[fst, snd]: segments)
		{
			const std::string &segname = fst;
			const std::vector<const SectionInfo2 *> &sections = snd;
			if (segname == "__PAGEZERO")
			{
				if (is_64bit)
				{
					SegmentCommand64 seg = {};
					memset(&seg, 0, sizeof(seg));
					seg.cmd = static_cast<uint32_t>(LoadCommandType::SEGMENT_64);
					seg.cmdsize = sizeof(SegmentCommand64);
					strncpy(seg.segname, segname.c_str(), 16);
					seg.vmaddr = 0;
					seg.vmsize = 0x100000000; /* 4GB */
					seg.fileoff = 0;
					seg.filesize = 0;
					seg.maxprot = 0;
					seg.initprot = 0;
					seg.nsects = 0;
					seg.flags = 0;

					file.write(reinterpret_cast<const char *>(&seg), sizeof(seg));
				}
				else
				{
					SegmentCommand32 seg;
					memset(&seg, 0, sizeof(seg));
					seg.cmd = static_cast<uint32_t>(LoadCommandType::SEGMENT);
					seg.cmdsize = sizeof(SegmentCommand32);
					strncpy(seg.segname, segname.c_str(), 16);
					seg.vmaddr = 0;
					seg.vmsize = 0xFFFFFFFF;
					seg.fileoff = 0;
					seg.filesize = 0;
					seg.maxprot = 0;
					seg.initprot = 0;
					seg.nsects = 0;
					seg.flags = 0;

					file.write(reinterpret_cast<const char *>(&seg), sizeof(seg));
				}
				continue;
			}

			uint64_t segaddr = 0;
			uint64_t segsize = 0;
			uint64_t segfileoff = file_offset;
			uint64_t segfilesize = 0;
			if (!sections.empty())
			{
				segaddr = sections[0]->addr;
				for (const auto *sect: sections)
				{
					segsize = std::max(segsize, sect->addr + sect->size - segaddr);
					segfilesize += sect->size;
				}
			}

			if (is_64bit)
			{
				SegmentCommand64 seg = {};
				memset(&seg, 0, sizeof(seg));
				seg.cmd = static_cast<uint32_t>(LoadCommandType::SEGMENT_64);
				seg.cmdsize = sizeof(SegmentCommand64) + sections.size() * sizeof(Section64);
				strncpy(seg.segname, segname.c_str(), 16);
				seg.vmaddr = segaddr;
				seg.vmsize = segsize;
				seg.fileoff = segname == "__LINKEDIT" ? file_offset : segfileoff;
				seg.filesize = segname == "__LINKEDIT" ? 0 : segfilesize;
				seg.maxprot = 7; /* RW-X- */
				seg.initprot = 7; /* RW-X- */
				seg.nsects = sections.size();
				seg.flags = 0;

				file.write(reinterpret_cast<const char *>(&seg), sizeof(seg));
				uint64_t sect_offset = file_offset;
				for (const auto *sect: sections)
				{
					Section64 section = {};
					memset(&section, 0, sizeof(section));
					strncpy(section.sectname, sect->sectname.c_str(), 16);
					strncpy(section.segname, sect->segname.c_str(), 16);
					section.addr = sect->addr;
					section.size = sect->size;
					section.offset = sect_offset;
					section.align = sect->align;
					section.reloff = 0; /* final executable shouldn't have relocations by any means */
					section.nreloc = 0;
					section.flags = sect->flags;
					section.reserved1 = 0;
					section.reserved2 = 0;
					section.reserved3 = 0;

					file.write(reinterpret_cast<const char *>(&section), sizeof(section));
					sect_offset += sect->size;
				}
			}
			else
			{
				/* __LINKEDIT has codesigning thing here */
				SegmentCommand32 seg = {};
				std::memset(&seg, 0, sizeof(seg));
				seg.cmd = static_cast<uint32_t>(LoadCommandType::SEGMENT);
				seg.cmdsize = sizeof(SegmentCommand32) + sections.size() * sizeof(Section32);
				strncpy(seg.segname, segname.c_str(), 16);
				seg.vmaddr = static_cast<uint32_t>(segaddr);
				seg.vmsize = static_cast<uint32_t>(segsize);
				seg.fileoff = static_cast<uint32_t>(segname == "__LINKEDIT" ? file_offset : segfileoff);
				seg.filesize = static_cast<uint32_t>(segname == "__LINKEDIT" ? 0 : segfilesize);
				seg.maxprot = 7; /* RW-X- */
				seg.initprot = 7; /* RW-X- */
				seg.nsects = sections.size();
				seg.flags = 0;

				file.write(reinterpret_cast<const char *>(&seg), sizeof(seg));
				auto sect_offset = static_cast<uint32_t>(file_offset);
				for (const auto *sect: sections)
				{
					Section32 section = {};
					memset(&section, 0, sizeof(section));
					strncpy(section.sectname, sect->sectname.c_str(), 16);
					strncpy(section.segname, sect->segname.c_str(), 16);
					section.addr = static_cast<uint32_t>(sect->addr);
					section.size = static_cast<uint32_t>(sect->size);
					section.offset = sect_offset;
					section.align = sect->align;
					section.reloff = 0; /* final executable shouldn't have relocations by any means */
					section.nreloc = 0;
					section.flags = sect->flags;
					section.reserved1 = 0;
					section.reserved2 = 0;

					file.write(reinterpret_cast<const char *>(&section), sizeof(section));
					sect_offset += static_cast<uint32_t>(sect->size);
				}
			}

			if (segname != "__LINKEDIT" && !sections.empty())
				file_offset += segfilesize;
		}

		uint64_t symtab_offset = file_offset;
		uint32_t nsyms = symbol_addresses.size();
		uint64_t strtab_offset = symtab_offset + nsyms * (is_64bit ? sizeof(Nlist64) : sizeof(Nlist32));

		uint32_t strtab_size = 1; /* skip the first byte since it's always zero */
		for (const auto &sym: symbol_addresses)
			strtab_size += sym.first.size() + 1; /* account + 1 for null terminator */

		SymtabCommand symtab = {};
		symtab.cmd = static_cast<uint32_t>(LoadCommandType::SYMTAB);
		symtab.cmdsize = sizeof(SymtabCommand);
		symtab.symoff = static_cast<uint32_t>(symtab_offset);
		symtab.nsyms = nsyms;
		symtab.stroff = static_cast<uint32_t>(strtab_offset);
		symtab.strsize = strtab_size;

		file.write(reinterpret_cast<const char *>(&symtab), sizeof(symtab));

		/* write to LC_MAIN */
		EntryPointCommand main_cmd = {};
		main_cmd.cmd = static_cast<uint32_t>(LoadCommandType::MAIN);
		main_cmd.cmdsize = sizeof(EntryPointCommand);
		if (auto main_it = symbol_addresses.find("_main");
			main_it != symbol_addresses.end())
			main_cmd.entryoff = main_it->second - 0x100000000; /* offset from start of __TEXT segment */
		else
			main_cmd.entryoff = 0; /* default of __TEXT */
		main_cmd.stacksize = 0; /* default stack size */

		file.write(reinterpret_cast<const char *>(&main_cmd), sizeof(main_cmd));
		for (const auto &sect: sections)
		{
			if ((sect.flags & static_cast<uint32_t>(SectionType::ZEROFILL)) == 0 && !sect.data.empty())
				file.write(reinterpret_cast<const char *>(sect.data.data()), sect.data.size());
		}

		std::vector<char> strtab(strtab_size, 0);
		uint32_t str_offset = 1; /* skip the first byte since it's always 0 */

		std::map<std::string, uint32_t> string_offsets;
		for (const auto &sym_pair: symbol_addresses)
		{
			const std::string &name = sym_pair.first;
			string_offsets[name] = str_offset;
			strcpy(strtab.data() + str_offset, name.c_str());
			str_offset += name.size() + 1;
		}

		/* write to symbol table */
		file.seekp(symtab_offset);
		for (const auto &sym_pair: symbol_addresses)
		{
			const std::string &name = sym_pair.first;
			uint64_t addr = sym_pair.second;
			uint8_t type = static_cast<uint8_t>(SymbolType::SECT) | static_cast<uint8_t>(SymbolFlags::EXT);
			uint8_t sect = 0;
			for (size_t i = 0; i < sections.size(); i++)
			{
				if (const auto &sect_info = sections[i];
					addr >= sect_info.addr && addr < sect_info.addr + sect_info.size)
				{
					sect = i + 1; /* 1-based index :( */
					break;
				}
			}

			if (is_64bit)
			{
				Nlist64 sym = {};
				sym.n_strx = string_offsets[name];
				sym.n_type = type;
				sym.n_sect = sect;
				sym.n_desc = 0;
				sym.n_value = addr;

				file.write(reinterpret_cast<const char *>(&sym), sizeof(sym));
			}
			else
			{
				Nlist32 sym = {};
				sym.n_strx = string_offsets[name];
				sym.n_type = type;
				sym.n_sect = sect;
				sym.n_desc = 0;
				sym.n_value = static_cast<uint32_t>(addr);

				file.write(reinterpret_cast<const char *>(&sym), sizeof(sym));
			}
		}

		file.write(strtab.data(), strtab.size());
		file.close();
		return true;
	}

	/* static variable initialization */
	std::vector<SectionInfo2> MachoLinker::output_sections;
}
