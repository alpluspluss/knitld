/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <cstdint>
#include <vector>

namespace knt
{
	/* magic number for different architectures */
	enum class Magic : std::uint32_t
	{
		MH_MAGIC = 0xFEEDFACE,
		MH_CIGAM = 0xCEFAEDFE,
		MH_MAGIC_64 = 0xFEEDFACF,
		MH_CIGAM_64 = 0xCFFAEDFE,
		FAT_MAGIC = 0xCAFEBABE,
		FAT_CIGAM = 0xBEBAFECA
	};

	/* cpu types */
	enum class CpuType : std::uint32_t
	{
		X86 = 7,
		X86_64 = 0x01000007,
		ARM = 12,
		ARM64 = 0x0100000c,
		POWERPC = 18,
		POWERPC64 = 0x01000012
	};

	/* file types */
	enum class FileType : std::uint8_t
	{
		OBJECT = 1,
		EXECUTE = 2,
		FVMLIB = 3,
		CORE = 4,
		PRELOAD = 5,
		DYLIB = 6,
		DYLINKER = 7,
		BUNDLE = 8,
		DYLIB_STUB = 9,
		DSYM = 10,
		KEXT_BUNDLE = 11,
		FILESET = 12
	};

	/* load command types */
	enum class LoadCommandType : std::uint32_t
	{
		SEGMENT = 0x1,
		SYMTAB = 0x2,
		DYSYMTAB = 0xB,
		SEGMENT_64 = 0x19,
		MAIN = 0x28,
		LOAD_DYLIB = 0xc,
		ID_DYLIB = 0xd,
		UUID = 0x1b,
		VERSION_MIN_MACOSX = 0x24,
		VERSION_MIN_IPHONEOS = 0x25,
		BUILD_VERSION = 0x32,
		DYLD_INFO = 0x22,
		DYLD_INFO_ONLY = 0x80000022,
		FUNCTION_STARTS = 0x26,
		DATA_IN_CODE = 0x29,
		CODE_SIGNATURE = 0x1d,
		DYLD_EXPORTS_TRIE = 0x80000033,
		DYLD_CHAINED_FIXUPS = 0x80000034
	};

	/* symbol types */
	enum class SymbolType : std::uint8_t
	{
		UNDF = 0x0, /* undefined */
		ABS = 0x2,  /* absolute */
		SECT = 0xe, /* defined in section */
		PBUD = 0xc, /* pre-bound undefined */
		NINDR = 0xa /* indirect */
	};

	/* symbol flags */
	enum class SymbolFlags
	{
		STAB = 0xe0, /* symbolic debugging entry */
		PEXT = 0x10, /* private external */
		TYPE = 0x0e, /* mask for type bits */
		EXT = 0x01   /* external */
	};

	/* section types and attributes */
	enum class SectionType : std::uint32_t
	{
		REGULAR = 0x0,
		ZEROFILL = 0x1,
		CSTRING_LITERALS = 0x2,
		LITERAL_POINTERS = 0x5,
		NON_LAZY_SYMBOL_POINTERS = 0x6,
		LAZY_SYMBOL_POINTERS = 0x7,
		SYMBOL_STUBS = 0x8,
		MOD_INIT_FUNC_POINTERS = 0x9,
		MOD_TERM_FUNC_POINTERS = 0xA,
		COALESCED = 0xB,
		GB_ZEROFILL = 0xC,
		INTERPOSING = 0xD,
		LITERALS_16B = 0xE,
		DTRACE_DOF = 0xF,
		LAZY_DYLIB_SYMBOL_POINTERS = 0x10
	};

	enum class SectionAttributes : std::uint32_t
	{
		PURE_INSTRUCTIONS = 0x80000000,
		NO_TOC = 0x40000000,
		STRIP_STATIC_SYMS = 0x20000000,
		NO_DEAD_STRIP = 0x10000000,
		LIVE_SUPPORT = 0x08000000,
		SELF_MODIFYING_CODE = 0x04000000,
		DEBUG = 0x02000000,
		SOME_INSTRUCTIONS = 0x00000400,
		EXT_RELOC = 0x00000200,
		LOC_RELOC = 0x00000100
	};

	/* relocation types */
	enum class RelocationType : std::uint32_t
	{
		X86_64_RELOC_UNSIGNED = 0,   /* absolute address */
		X86_64_RELOC_SIGNED = 1,     /* signed 32-bit */
		X86_64_RELOC_BRANCH = 2,     /* branch displacement */
		X86_64_RELOC_GOT_LOAD = 3,   /* load from GOT */
		X86_64_RELOC_GOT = 4,        /* GOT entry */
		X86_64_RELOC_SUBTRACTOR = 5, /* pair subtract */
		X86_64_RELOC_SIGNED_1 = 6,   /* signed 32-bit displacement -1 */
		X86_64_RELOC_SIGNED_2 = 7,   /* signed 32-bit displacement -2 */
		X86_64_RELOC_SIGNED_4 = 8,   /* signed 32-bit displacement -4 */
		X86_64_RELOC_TLV = 9,

		ARM64_RELOC_UNSIGNED = 0,          /* for pointers */
		ARM64_RELOC_SUBTRACTOR = 1,        /* must be followed by ARM64_RELOC_UNSIGNED */
		ARM64_RELOC_BRANCH26 = 2,          /* B/BL instruction with 26-bit displacement */
		ARM64_RELOC_PAGE21 = 3,            /* PC-rel distance to page of target */
		ARM64_RELOC_PAGEOFF12 = 4,         /* offset within page, scaled by r_length */
		ARM64_RELOC_GOT_LOAD_PAGE21 = 5,   /* PC-rel distance to page of GOT slot */
		ARM64_RELOC_GOT_LOAD_PAGEOFF12 = 6, /* offset within page of GOT slot */
		ARM64_RELOC_POINTER_TO_GOT = 7, /* pointers to GOT slots */
		ARM64_RELOC_TLVP_LOAD_PAGE21 = 8, /* PC relative distance to page of TLVP slot. */
		ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9, /* Offset within page of TLVP slot; scaled by r_length */
		ARM64_RELOC_ADDEND = 10, /* note: must be followed by `ARM64_RELOC_PAGE21` or `ARM64_RELOC_PAGEOFF12` */
		ARM64_RELOC_AUTHENTICATED_POINTER = 11
	};

	/* header structures */
	struct Header32
	{
		std::uint32_t magic;
		std::uint32_t cputype;
		std::uint32_t cpusubtype;
		std::uint32_t filetype;
		std::uint32_t ncmds;
		std::uint32_t sizeofcmds;
		std::uint32_t flags;
	};

	struct Header64
	{
		std::uint32_t magic;
		std::uint32_t cputype;
		std::uint32_t cpusubtype;
		std::uint32_t filetype;
		std::uint32_t ncmds;
		std::uint32_t sizeofcmds;
		std::uint32_t flags;
		std::uint32_t reserved;
	};

	struct FatHeader
	{
		std::uint32_t magic;
		std::uint32_t nfat_arch;
	};

	struct FatArch
	{
		std::uint32_t cputype;
		std::uint32_t cpusubtype;
		std::uint32_t offset;
		std::uint32_t size;
		std::uint32_t align;
	};

	struct LoadCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
	};

	struct SegmentCommand32
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		char segname[16];
		std::uint32_t vmaddr;
		std::uint32_t vmsize;
		std::uint32_t fileoff;
		std::uint32_t filesize;
		std::uint32_t maxprot;
		std::uint32_t initprot;
		std::uint32_t nsects;
		std::uint32_t flags;
	};

	struct SegmentCommand64
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		char segname[16];
		std::uint64_t vmaddr;
		std::uint64_t vmsize;
		std::uint64_t fileoff;
		std::uint64_t filesize;
		std::uint32_t maxprot;
		std::uint32_t initprot;
		std::uint32_t nsects;
		std::uint32_t flags;
	};

	struct Section32
	{
		char sectname[16];
		char segname[16];
		std::uint32_t addr;
		std::uint32_t size;
		std::uint32_t offset;
		std::uint32_t align;
		std::uint32_t reloff;
		std::uint32_t nreloc;
		std::uint32_t flags;
		std::uint32_t reserved1;
		std::uint32_t reserved2;
	};

	struct Section64
	{
		char sectname[16];
		char segname[16];
		std::uint64_t addr;
		std::uint64_t size;
		std::uint32_t offset;
		std::uint32_t align;
		std::uint32_t reloff;
		std::uint32_t nreloc;
		std::uint32_t flags;
		std::uint32_t reserved1;
		std::uint32_t reserved2;
		std::uint32_t reserved3;
	};

	struct SymtabCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint32_t symoff;  /* file offset to symbol table */
		std::uint32_t nsyms;   /* number of symbol table entries */
		std::uint32_t stroff;  /* file offset to string table */
		std::uint32_t strsize; /* string table size in bytes */
	};

	struct DysymtabCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint32_t ilocalsym;      /* index to local symbols */
		std::uint32_t nlocalsym;      /* number of local symbols */
		std::uint32_t iextdefsym;     /* index to externally defined symbols */
		std::uint32_t nextdefsym;     /* number of externally defined symbols */
		std::uint32_t iundefsym;      /* index to undefined symbols */
		std::uint32_t nundefsym;      /* number of undefined symbols */
		std::uint32_t tocoff;         /* file offset to table of contents */
		std::uint32_t ntoc;           /* number of entries in TOC */
		std::uint32_t modtaboff;      /* file offset to module table */
		std::uint32_t nmodtab;        /* number of entries in module table */
		std::uint32_t extrefsymoff;   /* offset to referenced symbol table */
		std::uint32_t nextrefsyms;    /* number of referenced symbol table entries */
		std::uint32_t indirectsymoff; /* file offset to indirect symbol table */
		std::uint32_t nindirectsyms;  /* number of indirect symbol table entries */
		std::uint32_t extreloff;      /* offset to external relocation entries */
		std::uint32_t nextrel;        /* number of external relocation entries */
		std::uint32_t locreloff;      /* offset to local relocation entries */
		std::uint32_t nlocrel;        /* number of local relocation entries */
	};

	struct DyldInfoCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint32_t rebase_off;
		std::uint32_t rebase_size;
		std::uint32_t bind_off;
		std::uint32_t bind_size;
		std::uint32_t weak_bind_off;
		std::uint32_t weak_bind_size;
		std::uint32_t lazy_bind_off;
		std::uint32_t lazy_bind_size;
		std::uint32_t export_off;
		std::uint32_t export_size;
	};

	struct Nlist32
	{
		std::uint32_t n_strx;  /* index into string table */
		std::uint8_t n_type;   /* type flag */
		std::uint8_t n_sect;   /* section number or NO_SECT */
		std::int16_t n_desc;   /* see <mach-o/stab.h> */
		std::uint32_t n_value; /* value of symbol (usually addr) */
	};

	struct Nlist64
	{
		std::uint32_t n_strx;  /* index into string table */
		std::uint8_t n_type;   /* type flag */
		std::uint8_t n_sect;   /* section number or NO_SECT */
		std::uint16_t n_desc;  /* see #include <mach-o/stab.h> */
		std::uint64_t n_value; /* value of symbol (usually addr) */
	};

	struct RelocationInfo
	{
		std::int32_t r_address;        /* offset in section to what is being relocated */
		std::uint32_t r_symbolnum: 24, /* symbol index if r_extern=1 or section if r_extern=0 */
				r_pcrel: 1,            /* was relocated pc relative */
				r_length: 2,           /* 0=byte, 1=word, 2=long, 3=quad */
				r_extern: 1,           /* does not include value of sym referenced */
				r_type: 4;             /* if not 0, machine specific relocation type */
	};

	struct DylibCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint32_t name_offset;
		std::uint32_t timestamp;
		std::uint32_t current_version;
		std::uint32_t compatibility_version;
	};

	struct UuidCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint8_t uuid[16];
	};

	struct EntryPointCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint64_t entryoff;
		std::uint64_t stacksize;
	};

	struct BuildVersionCommand
	{
		std::uint32_t cmd;
		std::uint32_t cmdsize;
		std::uint32_t platform;
		std::uint32_t minos;
		std::uint32_t sdk;
		std::uint32_t ntools;
	};

	struct SymbolInfo
	{
		std::string name;
		std::uint64_t value; /* symbol value OR address */
		std::uint8_t type;   /* N_TYPE | N_STAB etc.  */
		std::uint8_t sect;   /* section index OR nosect */
		std::uint16_t desc;
		bool is_extern;
		bool is_undefined;
		bool is_common;
		bool is_weak;
		std::uint64_t common_size;
		std::uint8_t common_align;
	};

	struct SectionInfo
	{
		std::string segname;
		std::string sectname;
		std::uint64_t addr;
		std::uint64_t size;
		std::uint32_t offset;
		std::uint32_t align;
		std::uint32_t reloff;
		std::uint32_t nreloc;
		std::uint32_t flags;
		std::uint32_t reserved1;
		std::uint32_t reserved2;
		std::uint32_t reserved3; /* note: only for 64-bit */
		std::vector<std::uint8_t> data;
		std::vector<RelocationInfo> relocations;
	};

	struct SegmentInfo
	{
		std::string name;
		std::uint64_t vmaddr;
		std::uint64_t vmsize;
		std::uint64_t fileoff;
		std::uint64_t filesize;
		std::uint32_t maxprot;
		std::uint32_t initprot;
		std::uint32_t flags;
		std::vector<SectionInfo> sections;
	};

	struct IndirectSymbolInfo
	{
		std::uint32_t symbol_index;
		std::string symbol_name;
	};
}
