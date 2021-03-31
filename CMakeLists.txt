cmake_minimum_required(VERSION 3.10)

project(pdbdef)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

find_package(fmt REQUIRED)
find_package(CURL REQUIRED)

set(SRC_FILES
	src/pdbdef.cpp
	src/pdb.cpp
	src/pe.cpp
	src/curl.cpp)

add_executable(pdbdef ${SRC_FILES})

if(NOT MSVC)
	target_compile_options(pdbdef PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
endif()

target_link_libraries(pdbdef fmt::fmt-header-only)

target_include_directories(pdbdef PUBLIC "${CURL_INCLUDE_DIRS}")
target_link_libraries(pdbdef ${CURL_LIBRARIES})

install(TARGETS pdbdef DESTINATION bin)
