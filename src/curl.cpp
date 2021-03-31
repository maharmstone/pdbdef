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

#include <curl/curl.h>
#include <filesystem>
#include <string>
#include <fstream>

using namespace std;

static size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto& h = *(ofstream*)userdata;

    h.write(ptr, size * nmemb);

    return size * nmemb;
}

void download_file(const string& url, const filesystem::path& dest) {
    CURL* curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    try {
        curl = curl_easy_init();

        if (!curl)
            throw runtime_error("Failed to initialize cURL.");

        try {
            long error_code;

            {
                ofstream h(dest, ios::binary);

                if (!h.good())
                    throw runtime_error("Could not open " + dest.string() + " for writing.");

                h.exceptions(ofstream::failbit | ofstream::badbit);

                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
                curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, ""); // everything that libcurl supports

                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &h);

                res = curl_easy_perform(curl);

                if (res != CURLE_OK)
                    throw runtime_error(curl_easy_strerror(res));
            }

            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &error_code); // FIXME - only do if HTTP or HTTPS?

            if (error_code >= 400)
                throw runtime_error("HTTP error " + to_string(error_code));
        } catch (...) {
            curl_easy_cleanup(curl);
            throw;
        }

        curl_easy_cleanup(curl);
    } catch (...) {
        curl_global_cleanup();
        throw;
    }

    curl_global_cleanup();
}
