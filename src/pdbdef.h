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

#include <string>
#include <unordered_map>
#include <filesystem>

using labels_type = std::unordered_map<uint64_t, std::vector<std::string>>;

class formatted_error : public std::exception {
public:
    template<typename T, typename... Args>
    formatted_error(const T& s, Args&&... args) {
        msg = fmt::format(s, std::forward<Args>(args)...);
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    std::string msg;
};

// curl.cpp
void download_file(const std::string& url, const std::filesystem::path& dest);
