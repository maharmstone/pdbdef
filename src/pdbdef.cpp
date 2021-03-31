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

#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <map>
#include <unordered_set>
#include "pdb.h"
#include "pe.h"
#include "pdbdef.h"

using namespace std;

static void syms_to_labels(pdb& p, pe& img, labels_type& labels) {
    auto syms = p.read_symbols();

    for (const auto& sym : syms) {
        const auto& sect = img.sections[sym.section - 1];
        uint64_t off = img.base_addr + sect.VirtualAddress + sym.offset;

        if (labels.count(off) == 0)
            labels.insert(make_pair(off, vector<string>{ sym.name }));
        else {
            auto& l = labels.at(off);

            l.emplace_back(sym.name);
        }
    }
}

static void try_pdb(const filesystem::path& p, const pe_pdb_info& info, unique_ptr<pdb>& up) {
    up.reset(new pdb(p));

    auto info2 = up->get_info();

    if (memcmp(info2.guid, info.guid, sizeof(info.guid))) {
        throw formatted_error("different GUID ({:08x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x})",
                              *(uint32_t*)&info2.guid[0], *(uint16_t*)&info2.guid[4], *(uint16_t*)&info2.guid[6],
                              (uint8_t)info2.guid[8], (uint8_t)info2.guid[9], (uint8_t)info2.guid[10], (uint8_t)info2.guid[11],
                              (uint8_t)info2.guid[12], (uint8_t)info2.guid[13], (uint8_t)info2.guid[14], (uint8_t)info2.guid[15]);
    }
}

static filesystem::path get_cache_dir() {
    if (!getenv("HOME"))
        throw runtime_error("Cannot get cache directory as $HOME not set.");

    return getenv("HOME") + "/.cache/pdb"s;
}

static bool try_sympath(string_view sv, const pe_pdb_info& info, unique_ptr<pdb>& up, const string_view& name) {
    list<string_view> tokens;

    string path = fmt::format("{}/{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
                              name,
                              *(uint32_t*)&info.guid[0], *(uint16_t*)&info.guid[4], *(uint16_t*)&info.guid[6],
                              (uint8_t)info.guid[8], (uint8_t)info.guid[9], (uint8_t)info.guid[10], (uint8_t)info.guid[11],
                              (uint8_t)info.guid[12], (uint8_t)info.guid[13], (uint8_t)info.guid[14], (uint8_t)info.guid[15],
                              info.age, name);

    // FIXME - pd_ compressed format
    // FIXME - can have path with numeric component that isn't the GUID?

    do {
        auto star = sv.find("*");

        if (star == string::npos) {
            tokens.emplace_back(sv);
            break;
        }

        tokens.emplace_back(sv.substr(0, star));
        sv = sv.substr(star + 1);
    } while (true);

    if (tokens.front() == "srv" || tokens.front() == "symsrv") {
        if (tokens.front() == "symsrv") {
            tokens.pop_front();
            tokens.pop_front();
        } else
            tokens.pop_front();

        for (auto it = tokens.begin(); it != tokens.end(); it++) {
            const auto& t = *it;

            if ((t.length() >= 5 && t.substr(0, 5) == "http:") || (t.length() >= 6 && t.substr(0, 6) == "https:")) {
                filesystem::path cache_dir;
                bool found = false;

                if (it == tokens.begin() || prev(it)->empty())
                    cache_dir = get_cache_dir();
                else
                    cache_dir = string(*prev(it));

                // FIXME - throw error if previous token is URL

                filesystem::create_directories(cache_dir / path);

                string url = string(t) + "/"s + path + "/"s + string(name);

                fmt::print("Trying to download from {} ... ", url);

                filesystem::path fn = cache_dir / path / name;

                try {
                    download_file(url, fn);
                    try_pdb(fn, info, up);
                    fmt::print("success.\n");
                    found = true;
                } catch (const exception& e) {
                    fmt::print("{}\n", e.what());
                }

                if (found) {
                    fmt::print("Saved to {}.\n", fn.string());

                    if (it != tokens.begin() && prev(it) != tokens.begin()) { // copy to previous directories
                        auto it2 = prev(it, 2);

                        do {
                            filesystem::path t2 = *it2;
                            filesystem::path dest = t2 / path / name;
                            error_code ec;

                            filesystem::create_directories(t2 / path);
                            filesystem::copy(fn, dest, ec);

                            if (ec)
                                fmt::print(stderr, "Failed to copy to {}.\n", dest.string());
                            else
                                fmt::print("Copied to {}.\n", dest.string());

                            if (it2 == tokens.begin())
                                break;

                            it2--;
                        } while (true);
                    }

                    return true;
                }

                // remove duff cached file

                if (filesystem::exists(fn)) {
                    try {
                        filesystem::remove(fn);
                    } catch (...) {
                    }
                }

                // FIXME - rm created dir if tries and fails?
            } else {
                filesystem::path cache_dir;

                if (it == tokens.begin() && t.empty())
                    cache_dir = get_cache_dir();
                else
                    cache_dir = t;

                filesystem::path fn = cache_dir / path / name;

                if (exists(fn)) {
                    bool found = false;

                    fmt::print("Trying {} ... ", fn.string());

                    try {
                        try_pdb(fn, info, up);
                        fmt::print("success.\n");
                        found = true;
                    } catch (const exception& e) {
                        fmt::print("{}\n", e.what());
                    }

                    if (found) {
                        if (it != tokens.begin()) { // copy to previous directories
                            auto it2 = prev(it);

                            do {
                                filesystem::path t2 = *it2;
                                filesystem::path dest = t2 / path / name;
                                error_code ec;

                                filesystem::create_directories(t2 / path);
                                filesystem::copy(fn, dest, ec);

                                if (ec)
                                    fmt::print(stderr, "Failed to copy to {}.\n", dest.string());
                                else
                                    fmt::print("Copied to {}.\n", dest.string());

                                if (it2 == tokens.begin())
                                    break;

                                it2--;
                            } while (true);
                        }

                        return true;
                    }
                }
            }
        }
    } else
        fmt::print(stderr, "Unhandled symbol path token {}.", tokens.front());

    // FIXME - bare paths
    // FIXME - "cache"

    return false;
}

static void find_pdb_file(const pe_pdb_info& info, unique_ptr<pdb>& up) {
    string name = info.name;

    // if name contains backslashes, choose last element

    {
        auto pos = name.rfind("\\");

        if (pos != string::npos)
            name = name.substr(pos + 1);
    }

    string name_lc = name;

    transform(name_lc.begin(), name_lc.end(), name_lc.begin(), [](char c) {
        return tolower(c);
    });

    // search local directory case-insensitively

    for (auto& p : filesystem::directory_iterator(".")) {
        auto n = p.path().filename().string();

        transform(n.begin(), n.end(), n.begin(), [](char c) {
            return tolower(c);
        });

        if (name_lc == n) {
            fmt::print("Trying {}... ", p.path().string());

            try {
                try_pdb(p.path(), info, up);
                fmt::print("success.\n");
                return;
            } catch (const exception& e) {
                fmt::print("{}\n", e.what());
            }
        }
    }

    string sympath;

    if (getenv("_NT_SYMBOL_PATH"))
        sympath = getenv("_NT_SYMBOL_PATH");
    else {
        auto cache_dir = get_cache_dir();

        sympath = "srv*" + cache_dir.string() + "*http://msdl.microsoft.com/download/symbols";
    }

    string_view left = sympath;

    do {
        auto sc = left.find(";");
        string_view sv;

        if (sc == string::npos)
            sv = left;
        else
            sv = left.substr(0, sc);

        if (try_sympath(sv, info, up, name))
            return;

        if (sc == string::npos)
            throw runtime_error("No suitable PDB found.");

        left = left.substr(sc + 1);
    } while (true);

    throw runtime_error("No suitable PDB found.");
}

struct img_export {
    img_export(unsigned int ordinal, const string_view& name, uint32_t addr, const string_view& fwd) :
        ordinal(ordinal), name(name), addr(addr), fwd(fwd) { }

    unsigned int ordinal;
    string name;
    uint32_t addr;
    string fwd;
};

static vector<img_export> get_exports(pe& img) {
    auto dir = img.get_directory(IMAGE_DIRECTORY_ENTRY_EXPORT);

    if (dir.empty())
        return {};

    vector<img_export> exports;

    auto ied = (IMAGE_EXPORT_DIRECTORY*)dir.data();

    if (ied->NumberOfFunctions == 0)
        return {};

    auto functions = (uint32_t*)(img.data.data() + img.va_to_offset(ied->AddressOfFunctions));

    for (unsigned int i = 0; i < ied->NumberOfFunctions; i++) {
        if (functions[i] != 0) {
            if (img.addr_within_directory(IMAGE_DIRECTORY_ENTRY_EXPORT, functions[i])) { // forward
                char* fwd = img.data.data() + img.va_to_offset(functions[i]);

                exports.emplace_back(i + ied->Base, "", 0, fwd);
            } else
                exports.emplace_back(i + ied->Base, "", functions[i], "");
        }
    }

    if (ied->NumberOfNames != 0) {
        auto ords = (uint16_t*)(img.data.data() + img.va_to_offset(ied->AddressOfNameOrdinals));
        auto ptrs = (uint32_t*)(img.data.data() + img.va_to_offset(ied->AddressOfNames));

        for (unsigned int i = 0; i < ied->NumberOfNames; i++) {
            auto name = (char*)(img.data.data() + img.va_to_offset(ptrs[i]));
            for (auto& e : exports) {
                if (e.ordinal == ords[i] + ied->Base) {
                    e.name = name;
                    break;
                }
            }
        }
    }

    return exports;
}

static string demangle_name(string_view sv) {
    if (!sv.empty() && sv[0] == '_')
        sv = sv.substr(1);

    auto at = sv.find_last_of('@');

    if (at != string::npos && at != sv.length() - 1) { // remove at sign and trailing number
        bool rm_num = true;

        for (auto i = at + 1; i < sv.length(); i++) {
            if (sv[i] < '0' || sv[i] > '9') {
                rm_num = false;
                break;
            }
        }

        if (rm_num)
            sv = sv.substr(0, at);
    }

    return string{sv};
}

static void write_def_file(pe& img, const filesystem::path& img_fn, const vector<img_export>& exports,
                           labels_type& labels) {
    auto fn = img_fn;

    fn.replace_extension("def");

    fmt::print("Writing {}... ", fn.string());

    ofstream f(fn);

    f << "EXPORTS\n";

    for (const auto& e : exports) {
        if (e.fwd.empty() && labels.count(img.base_addr + e.addr) == 0) {
            if (!e.name.empty())
                fmt::print(stderr, "No label for export {} ({:x}).\n", e.name, img.base_addr + e.addr);
            else
                fmt::print(stderr, "No label for export {} ({:x}).\n", e.ordinal, img.base_addr + e.addr);

            continue;
        }

        if (!e.fwd.empty()) {
            if (e.name.empty())
                f << fmt::format("    {} @{} NONAME\n", e.fwd, e.ordinal);
            else
                f << fmt::format("    {} = {} @{}\n", e.name, e.fwd, e.ordinal);
        } else {
            auto& l = labels.at(img.base_addr + e.addr);

            auto dmn = demangle_name(l[0]);

            if (e.name.empty())
                f << fmt::format("    {} @{} NONAME\n", dmn, e.ordinal);
            else if (dmn == e.name)
                f << fmt::format("    {} @{}\n", dmn, e.ordinal);
            else
                f << fmt::format("    {} = {} @{}\n", e.name, dmn, e.ordinal);
        }
    }

    fmt::print("done\n");
}

static void pdbdef(const filesystem::path& img_fn) {
    pe img(img_fn);

    auto pdb_info = img.get_pdb_info();

    fmt::print("Found PDB information:\n    guid = {:08x}-{:04x}-{:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\n    age = {}\n    name = {}\n",
               *(uint32_t*)&pdb_info.guid[0], *(uint16_t*)&pdb_info.guid[4], *(uint16_t*)&pdb_info.guid[6],
               (uint8_t)pdb_info.guid[8], (uint8_t)pdb_info.guid[9], (uint8_t)pdb_info.guid[10], (uint8_t)pdb_info.guid[11],
               (uint8_t)pdb_info.guid[12], (uint8_t)pdb_info.guid[13], (uint8_t)pdb_info.guid[14], (uint8_t)pdb_info.guid[15],
               pdb_info.age, pdb_info.name);

    unique_ptr<pdb> p;

    find_pdb_file(pdb_info, p);

    auto exports = get_exports(img);

    labels_type labels;

    syms_to_labels(*p, img, labels);

    if (!exports.empty())
        write_def_file(img, img_fn, exports, labels);
}

int main(int argc, char* argv[]) {
    if (argc < 2 || (argc >= 2 && !strcmp(argv[1], "--help"))) {
        fmt::print(stderr, "Usage: pdbdef <image>\n");
        return 1;
    }

    try {
        pdbdef(argv[1]);
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}
