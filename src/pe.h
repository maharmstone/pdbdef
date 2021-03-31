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

#define IMAGE_DOS_SIGNATURE             0x5a4d // "MZ"
#define IMAGE_NT_SIGNATURE              0x00004550 // "PE\0\0"

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[0];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[0];
} IMAGE_OPTIONAL_HEADER64;

enum class pe_architecture : uint16_t {
    IMAGE_FILE_MACHINE_I386 = 0x014c,
    IMAGE_FILE_MACHINE_R3000 = 0x0162,
    IMAGE_FILE_MACHINE_R4000 = 0x0166,
    IMAGE_FILE_MACHINE_R10000 = 0x0168,
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,
    IMAGE_FILE_MACHINE_ALPHA = 0x0184,
    IMAGE_FILE_MACHINE_SH3 = 0x01a2,
    IMAGE_FILE_MACHINE_SH3DSP = 0x01a3,
    IMAGE_FILE_MACHINE_SH3E = 0x01a4,
    IMAGE_FILE_MACHINE_SH4 = 0x01a6,
    IMAGE_FILE_MACHINE_SH5 = 0x01a8,
    IMAGE_FILE_MACHINE_ARM = 0x01c0,
    IMAGE_FILE_MACHINE_ARMV7 = 0x01c4,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_THUMB = 0x01c2,
    IMAGE_FILE_MACHINE_AM33 = 0x01d3,
    IMAGE_FILE_MACHINE_POWERPC = 0x01f0,
    IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
    IMAGE_FILE_MACHINE_IA64 = 0x0200,
    IMAGE_FILE_MACHINE_MIPS16 = 0x0266,
    IMAGE_FILE_MACHINE_ALPHA64 = 0x0284,
    IMAGE_FILE_MACHINE_MIPSFPU = 0x0366,
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
    IMAGE_FILE_MACHINE_TRICORE = 0x0520,
    IMAGE_FILE_MACHINE_CEF = 0x0cef,
    IMAGE_FILE_MACHINE_EBC = 0x0ebc,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_M32R = 0x9041,
    IMAGE_FILE_MACHINE_CEE = 0xc0ee
};

typedef struct {
    enum pe_architecture Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b

#pragma pack(push,1)

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    };
} IMAGE_NT_HEADERS;

#define IMAGE_DIRECTORY_ENTRY_EXPORT        0
#define IMAGE_DIRECTORY_ENTRY_DEBUG         6

#define PE_IMAGE_DEBUG_TYPE_CODEVIEW         2

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
} IMAGE_DEBUG_DIRECTORY;

#define CVINFO_PDB70_CVSIGNATURE 0x53445352 // "RSDS"

typedef struct {
    uint32_t CvSignature;
    uint8_t Signature[16];
    uint32_t Age;
    char Name[1];
} CV_INFO_PDB70;

struct pe_pdb_info {
    uint8_t guid[16];
    uint32_t age;
    std::string name;
};

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

class pe {
public:
    pe(const std::filesystem::path& fn);

    pe_pdb_info get_pdb_info();
    std::string_view get_directory(unsigned int i);
    uint64_t va_to_offset(uint64_t va);
    bool addr_within_directory(unsigned int i, uint32_t addr) const;

    IMAGE_SECTION_HEADER* sections;
    uint64_t base_addr;
    std::string data;
};
