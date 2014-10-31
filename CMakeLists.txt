project(vfs.hdhomerun)

cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR})

enable_language(CXX)

find_package(kodi REQUIRED)
find_package(kodiplatform REQUIRED)

include_directories(${KODI_INCLUDE_DIR}
                    ${KODIPLATFORM_INCLUDE_DIRS}
                    ${PROJECT_SOURCE_DIR}/lib/libhdhomerun)

set(HDH_SOURCES src/HDHomeRunFile.cpp)

add_subdirectory(lib/libhdhomerun)
set(DEPLIBS hdhomerun)

add_definitions(-D_LARGEFILE64_SOURCE
                -D_FILE_OFFSET_BITS=64
                -D__STDC_FORMAT_MACROS)

build_addon(vfs.hdhomerun HDH DEPLIBS)
