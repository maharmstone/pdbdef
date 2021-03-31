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

#include "pe.h"
#include <string.h>
#include "pdb.h"
#include "pdbdef.h"

using namespace std;

pe::pe(const filesystem::path& fn) {
    data.resize(file_size(fn));

    {
        ifstream f(fn);

        if (!f.good())
            throw formatted_error("Error opening file {}.", fn.u8string());

        f.read(data.data(), data.length());
    }

    auto& dos_header = *(IMAGE_DOS_HEADER*)data.data();

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        throw runtime_error("Incorrect DOS signature.");

    auto& nt_header = *(IMAGE_NT_HEADERS*)(data.data() + dos_header.e_lfanew);

    if (nt_header.Signature != IMAGE_NT_SIGNATURE)
        throw runtime_error("Incorrect PE signature.");

    if (nt_header.OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        nt_header.OptionalHeader32.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        throw runtime_error("Unrecognized optional header signature.");

    if (nt_header.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        base_addr = nt_header.OptionalHeader32.ImageBase;
    else
        base_addr = nt_header.OptionalHeader64.ImageBase;

    sections = (IMAGE_SECTION_HEADER*)((char*)&nt_header + offsetof(IMAGE_NT_HEADERS, OptionalHeader32) + nt_header.FileHeader.SizeOfOptionalHeader);
}

uint64_t pe::va_to_offset(uint64_t va) {
    auto& dos_header = *(IMAGE_DOS_HEADER*)data.data();
    auto& nt_header = *(IMAGE_NT_HEADERS*)(data.data() + dos_header.e_lfanew);

    for (unsigned int i = 0; i < nt_header.FileHeader.NumberOfSections; i++) {
        if (va >= sections[i].VirtualAddress && va < sections[i].VirtualAddress + sections[i].SizeOfRawData)
            return va - sections[i].VirtualAddress + sections[i].PointerToRawData;
    }

    throw formatted_error("Unable to get file offset of virtual address {:x}.", va);
}

pe_pdb_info pe::get_pdb_info() {
    auto sv = get_directory(IMAGE_DIRECTORY_ENTRY_DEBUG);

    if (sv.empty())
        throw runtime_error("No debug directory in image.");

    auto size = sv.size();
    auto idd = (IMAGE_DEBUG_DIRECTORY*)sv.data();

    while (size >= sizeof(IMAGE_DEBUG_DIRECTORY)) {
        if (idd->Type == PE_IMAGE_DEBUG_TYPE_CODEVIEW && idd->SizeOfData >= sizeof(CV_INFO_PDB70)) {
            auto addr = va_to_offset(idd->AddressOfRawData);

            auto cv_info = (CV_INFO_PDB70*)(data.data() + addr);

            if (cv_info->CvSignature != CVINFO_PDB70_CVSIGNATURE)
                fmt::print(stderr, "Unrecognized CodeView signature {:08x}, expected {:08x}\n", cv_info->CvSignature, CVINFO_PDB70_CVSIGNATURE);
            else {
                pe_pdb_info ret;

                memcpy(&ret.guid, cv_info->Signature, sizeof(cv_info->Signature));
                ret.age = cv_info->Age;
                ret.name = cv_info->Name;

                if (ret.name.empty())
                    throw runtime_error("CodeView debugging information found, but no PDB name set.");

                return ret;
            }
        }

        idd = &idd[1];
        size -= sizeof(IMAGE_DEBUG_DIRECTORY);
    }

    throw runtime_error("No CodeView debugging information found in image.");
}

string_view pe::get_directory(unsigned int i) {
    auto& dos_header = *(IMAGE_DOS_HEADER*)data.data();
    auto& nt_header = *(IMAGE_NT_HEADERS*)(data.data() + dos_header.e_lfanew);

    if (nt_header.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (nt_header.OptionalHeader64.NumberOfRvaAndSizes <= i ||
            nt_header.OptionalHeader64.DataDirectory[i].VirtualAddress == 0) {
            return {};
        }

        return {data.data() + va_to_offset(nt_header.OptionalHeader64.DataDirectory[i].VirtualAddress),
                nt_header.OptionalHeader64.DataDirectory[i].Size};
    } else {
        if (nt_header.OptionalHeader32.NumberOfRvaAndSizes <= i ||
            nt_header.OptionalHeader32.DataDirectory[i].VirtualAddress == 0) {
            return {};
        }

        return {data.data() + va_to_offset(nt_header.OptionalHeader32.DataDirectory[i].VirtualAddress),
                nt_header.OptionalHeader32.DataDirectory[i].Size};
    }

    return {};
}

bool pe::addr_within_directory(unsigned int i, uint32_t addr) const {
    auto& dos_header = *(IMAGE_DOS_HEADER*)data.data();
    auto& nt_header = *(IMAGE_NT_HEADERS*)(data.data() + dos_header.e_lfanew);

    uint32_t dir_addr, dir_size;

    if (nt_header.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (nt_header.OptionalHeader64.NumberOfRvaAndSizes <= i ||
            nt_header.OptionalHeader64.DataDirectory[i].VirtualAddress == 0) {
            return false;
        }

        dir_addr = nt_header.OptionalHeader64.DataDirectory[i].VirtualAddress;
        dir_size = nt_header.OptionalHeader64.DataDirectory[i].Size;
    } else {
        if (nt_header.OptionalHeader32.NumberOfRvaAndSizes <= i ||
            nt_header.OptionalHeader32.DataDirectory[i].VirtualAddress == 0) {
            return false;
        }

        dir_addr = nt_header.OptionalHeader32.DataDirectory[i].VirtualAddress;
        dir_size = nt_header.OptionalHeader32.DataDirectory[i].Size;
    }

    return addr >= dir_addr && addr < dir_addr + dir_size;
}
