/* this file is a part of Knit linker project; see LICENSE for more info */

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <knit/mach-o.hpp>
#include <knit/parser.hpp>

namespace knt
{
    struct ObjectFile
    {
        std::string path;
        MachoParser parser;

        explicit ObjectFile(std::string_view path) : path(path), parser(path)
        {
            parser.parse();
        }
    };

    struct SymbolResolution
    {
        const SymbolInfo *symbol;
        const SymbolInfo *resolved_to;
        ObjectFile *file;
        bool is_weak;
        bool is_common;
        std::uint64_t common_size;
        std::uint8_t common_align;

        SymbolResolution() : symbol(nullptr),
                             resolved_to(nullptr),
                             file(nullptr),
                             is_weak(false), is_common(false),
                             common_size(0), common_align(0) {}
    };

    struct SectionInfo2
    {
        std::string segname;
        std::string sectname;
        uint64_t addr;
        uint64_t size;
        uint32_t align;
        uint32_t flags;
        std::vector<uint8_t> data;

        struct SourceSection
        {
            ObjectFile* file;
            size_t index;
            uint64_t offset;
        };

        std::vector<SourceSection> sources;

        SectionInfo2() : addr(0), size(0), align(0), flags(0) {}
    };

    class MachoLinker
    {
    public:
        MachoLinker();

        void set_target_cpu(CpuType cpu);

        bool add_input(std::string_view path);

        bool proc();

        bool link(std::string_view out_path);

    private:
        CpuType target_cpu;
        bool is_64bit;
        std::vector<std::shared_ptr<ObjectFile>> input_files;
        std::map<std::string, SymbolResolution> defined_symbols;
        static std::vector<SectionInfo2> output_sections;

        std::uint64_t get_symbol_address(ObjectFile* file, const SymbolInfo& sym);

        void apply_relocations(std::vector<SectionInfo2>& sections,
                              const std::map<std::string, std::uint64_t>& symbol_addresses);

        void apply_relocation(SectionInfo2& sect, const SectionInfo2::SourceSection& source,
                             const SectionInfo& in_sect, const RelocationInfo& reloc,
                             const std::map<std::string, std::uint64_t>& symbol_addresses,
                             const ObjectFile* file);

        void apply_x86_64_relocation(const SectionInfo2& sect, std::uint64_t address, std::uint8_t* data_ptr,
                                   const RelocationInfo& reloc, std::uint64_t target_addr);

        void apply_x86_64_section_relocation(SectionInfo2& sect, std::uint64_t address, std::uint8_t* data_ptr,
                                           const RelocationInfo& reloc, std::uint64_t target_addr);

        static void apply_arm64_relocation(const SectionInfo2& sect, std::uint64_t address, std::uint8_t* data_ptr,
                                  const RelocationInfo& reloc, std::uint64_t target_addr);

        void apply_arm64_section_relocation(SectionInfo2& sect, std::uint64_t address, std::uint8_t* data_ptr,
                                          const RelocationInfo& reloc, std::uint64_t target_addr);

        bool write_output_file(std::string_view path, const std::vector<SectionInfo2>& sections,
                              const std::map<std::string, std::uint64_t>& symbol_addresses);
    };
}
