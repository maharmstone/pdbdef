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

#include "pdb.h"
#include "pdbdef.h"

using namespace std;

pdb::pdb(const filesystem::path& fn) : f(fn) {
    if (!f.good())
        throw formatted_error("Error opening file {}.", fn.u8string());

    f.read((char*)&super, sizeof(super));

    if (memcmp(super.magic, PDB_MAGIC, sizeof(PDB_MAGIC)))
        throw runtime_error("Invalid superblock magic.");

    auto block_map_str = read_block(super.block_map_addr);
    auto block_map = (uint32_t*)block_map_str.data();

    string blocks;

    for (unsigned int i = 0; i < (super.num_directory_bytes + super.block_size - 1) / super.block_size; i++) {
        if (block_map[i] == 0)
            break;

        blocks += read_block(block_map[i]);
    }

    if (blocks.empty())
        throw runtime_error("Blocks list was empty.");

    auto num_streams = *(uint32_t*)blocks.data();

    stream_list.resize(num_streams);

    auto sizes = (uint32_t*)(blocks.data() + sizeof(uint32_t));

    for (unsigned int i = 0; i < num_streams; i++) {
        stream_list[i].size = sizes[i];
    }

    auto addr = &sizes[num_streams];

    for (unsigned int i = 0; i < num_streams; i++) {
        if (stream_list[i].size == 0)
            continue;

        unsigned int block_count = (stream_list[i].size + super.block_size - 1) / super.block_size;

        stream_list[i].addresses.resize(block_count);

        memcpy(stream_list[i].addresses.data(), addr, block_count * sizeof(uint32_t));
        addr += block_count;
    }
}

string pdb::read_block(uint32_t addr) {
    string ret;

    auto pos = (uint64_t)addr * (uint64_t)super.block_size;

    f.seekg(pos);

    if (f.fail())
        throw formatted_error(FMT_STRING("Error seeking to {:x}."), pos);

    ret.resize(super.block_size);

    f.read(ret.data(), super.block_size);

    return ret;
}

string pdb::read_stream(unsigned int num) {
    if (num >= stream_list.size())
        throw formatted_error("Stream {} out of bounds.", num);

    string ret;
    uint32_t pos = 0;

    ret.resize(stream_list[num].size);

    for (auto a : stream_list[num].addresses) {
        auto block = read_block(a);

        memcpy(ret.data() + pos, block.data(), min(super.block_size, stream_list[num].size - pos));
        pos += super.block_size;
    }

    return ret;
}

list<symbol> pdb::read_symbols() {
    uint16_t stream_num;

    {
        auto dbi = read_stream(3);

        if (dbi.length() < sizeof(dbi_stream_header))
            throw formatted_error("DBI was {} bytes, expected at least {}.", dbi.length(), sizeof(dbi_stream_header));

        auto& h = *(dbi_stream_header*)dbi.data();

        if (h.version_signature != -1)
            throw formatted_error("DBI version signature was {}, expected -1.", h.version_signature);

        if (h.version_header != dbi_stream_version::dbi_stream_version_v70)
            throw formatted_error("DBI version was {}, expected dbi_stream_version_v70.", h.version_header);

        if (h.sym_record_stream == 0)
            return {};

        stream_num = h.sym_record_stream;
    }

    if (stream_num >= stream_list.size())
        throw formatted_error("Symbol record stream too large ({}, expected less than {}).", stream_num, stream_list.size());

    list<symbol> ret;

    auto data = read_stream(stream_num);

    auto sv = string_view(data);

    while (sv.length() > sizeof(uint32_t)) {
        auto size = *(uint16_t*)sv.data();

        if (size + sizeof(uint16_t) > sv.length())
            break;

        auto type = *(uint16_t*)(sv.data() + sizeof(uint16_t));

        if (type == S_PUB32) {
            auto h = (pub32*)(sv.data() + sizeof(uint16_t) + sizeof(uint16_t));
            string s = (char*)&h[1];

            ret.emplace_back(s, h->section, h->offset);
        }

        sv = sv.substr(size + sizeof(uint16_t));
    }

    return ret;
}

pdb_info pdb::get_info() {
    pdb_info ret;
    auto stream = read_stream(1);

    if (stream.length() < sizeof(pdb_info_header))
        throw formatted_error("Info stream too short ({}, expected at least {}.", stream.length(), sizeof(pdb_info_header));

    const auto& h = *(pdb_info_header*)stream.data();

    if (h.version != pdb_stream_version::pdb_stream_version_vc70)
        throw formatted_error("Version was {}, expected {}.", h.version, pdb_stream_version::pdb_stream_version_vc70);

    memcpy(&ret.guid, &h.guid, sizeof(h.guid));
    ret.age = h.age;

    return ret;
}
