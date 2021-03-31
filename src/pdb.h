/* Copyright (c) Mark Harmstone 2021
 *
 * This file is part of pdbdef.
 *
 * pdbdef is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public Licence as published by
 * the Free Software Foundation, either version 2 of the Licence, or
 * (at your option) any later version.
 *
 * pdbdef is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public Licence for more details.
 *
 * You should have received a copy of the GNU General Public Licence
 * along with pdbdef. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <list>
#include <fmt/format.h>

#define PDB_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\0\0"

#define S_PUB32         0x110e

struct pdb_superblock {
    char magic[sizeof(PDB_MAGIC)];
    uint32_t block_size;
    uint32_t free_block_map;
    uint32_t num_blocks;
    uint32_t num_directory_bytes;
    uint32_t unknown;
    uint32_t block_map_addr;
};

enum class dbi_stream_version : uint32_t {
    dbi_stream_version_vc41 = 930803,
    dbi_stream_version_v50 = 19960307,
    dbi_stream_version_v60 = 19970606,
    dbi_stream_version_v70 = 19990903,
    dbi_stream_version_v110 = 20091201
};

template<>
struct fmt::formatter<enum dbi_stream_version> {
    constexpr auto parse(format_parse_context& ctx) {
        auto it = ctx.begin();

        if (it != ctx.end() && *it != '}')
            throw format_error("invalid format");

        return it;
    }

    template<typename format_context>
    auto format(const enum dbi_stream_version& v, format_context& ctx) {
        switch (v) {
            case dbi_stream_version::dbi_stream_version_vc41:
                return format_to(ctx.out(), "dbi_stream_version_vc41");

            case dbi_stream_version::dbi_stream_version_v50:
                return format_to(ctx.out(), "dbi_stream_version_v50");

            case dbi_stream_version::dbi_stream_version_v60:
                return format_to(ctx.out(), "dbi_stream_version_v60");

            case dbi_stream_version::dbi_stream_version_v70:
                return format_to(ctx.out(), "dbi_stream_version_v70");

            case dbi_stream_version::dbi_stream_version_v110:
                return format_to(ctx.out(), "dbi_stream_version_v110");

            default:
                return format_to(ctx.out(), "{}", (uint32_t)v);
        }
    }
};

struct dbi_stream_header {
    int32_t version_signature;
    enum dbi_stream_version version_header;
    uint32_t age;
    uint16_t global_stream_index;
    uint16_t build_number;
    uint16_t public_stream_index;
    uint16_t pdb_dll_version;
    uint16_t sym_record_stream;
    uint16_t pdb_dll_rbld;
    int32_t mod_info_size;
    int32_t section_contribution_size;
    int32_t section_map_size;
    int32_t source_info_size;
    int32_t type_server_map_size;
    uint32_t mfc_type_server_index;
    int32_t optional_dbg_header_size;
    int32_t ec_substream_size;
    uint16_t flags;
    uint16_t machine;
    uint32_t padding;
};

static_assert(sizeof(struct dbi_stream_header) == 0x40, "dbi_stream_header has incorrect size");

struct dbi_section_contribution { // SC in cvdump
    uint16_t section;
    uint16_t padding1;
    uint32_t offset;
    uint32_t size;
    uint32_t characteristics;
    uint16_t module_index;
    uint16_t padding2;
    uint32_t data_crc;
    uint32_t reloc_crc;
};

struct stream {
    uint32_t size = 0;
    std::vector<uint32_t> addresses;
};

struct dbi_module_info { // MODI_60_Persist in cvdump
    uint32_t unused1;
    dbi_section_contribution sc;
    uint16_t written : 1;
    uint16_t ec_enabled : 1;
    uint16_t unused2 : 6;
    uint16_t tsm : 8;
    uint16_t module_stream;
    uint32_t symbols_size;
    uint32_t lines_size;
    uint32_t c13_lines_size;
    uint16_t source_file_count;
    uint16_t padding;
    uint32_t unused3;
    uint32_t source_file_name_index;
    uint32_t pdb_file_name_index;
};

struct symbol {
    symbol(const std::string& name, uint16_t section, uint32_t offset) : name(name), section(section), offset(offset) { }

    std::string name;
    uint16_t section;
    uint32_t offset;
};

#pragma pack(push,1)

struct pub32 {
    uint32_t flags;
    uint32_t offset;
    uint16_t section;
};

#pragma pack(pop)

static_assert(sizeof(pub32) == 10, "pub32 has wrong size");

enum class pdb_stream_version : uint32_t {
    pdb_stream_version_vc2 = 19941610,
    pdb_stream_version_vc4 = 19950623,
    pdb_stream_version_vc41 = 19950814,
    pdb_stream_version_vc50 = 19960307,
    pdb_stream_version_vc98 = 19970604,
    pdb_stream_version_vc70dep = 19990604,
    pdb_stream_version_vc70 = 20000404,
    pdb_stream_version_vc80 = 20030901,
    pdb_stream_version_vc110 = 20091201,
    pdb_stream_version_vc140 = 20140508,
};

struct pdb_info_header {
    enum pdb_stream_version version;
    uint32_t signature;
    uint32_t age;
    uint8_t guid[16];
};

struct pdb_info {
    uint8_t guid[16];
    uint32_t age;
};

class pdb {
public:
    pdb(const std::filesystem::path& fn);
    std::list<symbol> read_symbols();
    pdb_info get_info();

private:
    std::string read_block(uint32_t addr);
    std::string read_stream(unsigned int num);

    pdb_superblock super;
    std::ifstream f;
    std::vector<stream> stream_list;
};
