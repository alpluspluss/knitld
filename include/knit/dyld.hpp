/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <knit/mach-o.hpp>

namespace knt
{
	enum class BindOpcode : std::uint8_t
	{
		DONE = 0x00,
		SET_DYLIB_ORDINAL_IMM = 0x10,
		SET_DYLIB_ORDINAL_ULEB = 0x20,
		SET_DYLIB_SPECIAL_IMM = 0x30,
		SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40,
		SET_TYPE_IMM = 0x50,
		SET_ADDEND_SLEB = 0x60,
		SET_SEGMENT_AND_OFFSET_ULEB = 0x70,
		ADD_ADDR_ULEB = 0x80,
		DO_BIND = 0x90,
		DO_BIND_ADD_ADDR_ULEB = 0xA0,
		DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0,
		DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
	};

	enum class RebaseOpcode : std::uint8_t
	{
		DONE = 0x00,
		SET_TYPE_IMM = 0x10,
		SET_SEGMENT_AND_OFFSET_ULEB = 0x20,
		ADD_ADDR_ULEB = 0x30,
		ADD_ADDR_IMM_SCALED = 0x40,
		DO_REBASE_IMM_TIMES = 0x50,
		DO_REBASE_ULEB_TIMES = 0x60,
		DO_REBASE_ADD_ADDR_ULEB = 0x70,
		DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80
	};

	enum class RebaseType : std::uint8_t
	{
		POINTER = 1,
		TEXT_ABSOLUTE32 = 2,
		TEXT_PCREL32 = 3
	};

	enum class BindType : std::uint8_t
	{
		POINTER = 1,
		TEXT_ABSOLUTE32 = 2,
		TEXT_PCREL32 = 3
	};

	enum class BindSpecialDylib : std::int8_t
	{
		SELF = 0,
		MAIN_EXECUTABLE = -1,
		FLAT_LOOKUP = -2,
		WEAK_LOOKUP = -3
	};

	enum class BindSymbolFlags : std::uint8_t
	{
		WEAK_IMPORT = 0x1,
		NON_WEAK_DEFINITION = 0x8
	};

	constexpr uint32_t EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03;
	constexpr uint32_t EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04;
	constexpr uint32_t EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08;
	constexpr uint32_t EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10;

	struct BindInfo
	{
		BindType type;
		std::int8_t library_ordinal;
		std::uint8_t symbol_flags;
		std::string symbol_name;
		std::int64_t addend;
		std::uint8_t segment_index;
		std::uint64_t segment_offset;
		std::uint64_t address;
	};

	struct RebaseInfo
	{
		RebaseType type;
		std::uint8_t segment_index;
		std::uint64_t segment_offset;
		std::uint64_t address; /* computed from segment_index and segment_offset */
	};

	struct ExportInfo
	{
		std::string symbol_name;
		std::uint64_t address;
		std::uint32_t flags;
		std::int64_t other; /* used for re-exports */
		std::string other_name;
	};

	enum class ChainedFormat : std::uint32_t
	{
		NONE = 0,
		ARM64E = 1,
		PTR64 = 2,
		PTR32 = 3,
		PTR32_CACHE = 4,
		PTR32_FIRMWARE = 5,
		PTR64_OFFSET = 6,
		ARM64E_KERNEL = 7,
		PTR64_KERNEL_CACHE = 8,
		ARM64E_USERLAND = 9,
		ARM64E_FIRMWARE = 10,
		PTR64_KERNEL_CACHE_X86 = 11,
		ARM64E_USERLAND24 = 12
	};

	enum class ChainedImportFormat : std::uint32_t
	{
		NONE = 0,
		SIMPLE = 1,
		ADDEND = 2,
		ADDEND64 = 3
	};

	struct ChainedFixupsHeader
	{
		std::uint32_t fixups_version;
		std::uint32_t starts_offset;
		std::uint32_t imports_offset;
		std::uint32_t symbols_offset;
		std::uint32_t imports_count;
		std::uint32_t imports_format;
		std::uint32_t symbols_format;
	};

	struct ChainedStartsInSegment
	{
		std::uint32_t size;
		std::uint16_t page_size;
		std::uint16_t pointer_format;
		std::uint64_t segment_offset;
		std::uint32_t max_valid_pointer;
		std::uint16_t page_count;
		std::vector<std::uint16_t> page_starts;
	};

	struct ChainedStartsInImage
	{
		std::uint32_t seg_count;
		std::vector<std::uint32_t> seg_info_offset;
		std::vector<ChainedStartsInSegment> segments;
	};

	struct ChainedImport
	{
		std::uint32_t lib_ordinal: 8,
				weak_import: 1,
				name_offset: 23;
	};

	struct ChainedImportAddend
	{
		std::uint32_t lib_ordinal: 8,
				weak_import: 1,
				name_offset: 23;
		std::int32_t addend;
	};

	struct ChainedImportAddend64
	{
		std::uint64_t lib_ordinal: 16,
				weak_import: 1,
				reserved: 15,
				name_offset: 32;
		std::uint64_t addend;
	};

	struct DynamicLinkingInfo
	{
		std::vector<RebaseInfo> rebases;
		std::vector<BindInfo> binds;
		std::vector<BindInfo> weak_binds;
		std::vector<BindInfo> lazy_binds;

		bool has_chained_fixups;
		ChainedFixupsHeader chained_header;
		ChainedStartsInImage chained_starts;
		std::vector<BindInfo> chained_binds;

		std::vector<std::string> imported_libraries;

		DynamicLinkingInfo() : has_chained_fixups(false),
		                       chained_header(),
		                       chained_starts() {}
	};

	std::uint64_t read_uleb128(const std::uint8_t *data, std::size_t &offset);

	std::uint64_t read_sleb128(const std::uint8_t *data, std::size_t &offset);

	std::uint64_t compute_addr(const std::vector<SegmentInfo> &segs, std::uint8_t segment_index,
	                           std::uint64_t segment_offset);
}
