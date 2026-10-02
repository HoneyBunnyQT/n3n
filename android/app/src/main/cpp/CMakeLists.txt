# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# libn3n for the Android app: the edge's sources of the core, straight from
# src/ of this repository - so the app always builds with the current core -
# and the JNI glue.  The edge only, as ./configure --disable-relay builds it.

cmake_minimum_required(VERSION 3.18)
project(n3n C)

get_filename_component(TOP "${CMAKE_CURRENT_SOURCE_DIR}/../../../../.." ABSOLUTE)

# The core's version, as its Makefile has it
execute_process(
    COMMAND git describe --abbrev=7 --dirty
    WORKING_DIRECTORY ${TOP}
    OUTPUT_VARIABLE N3N_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
if(NOT N3N_VERSION)
    file(READ ${TOP}/VERSION N3N_VERSION)
    string(STRIP "${N3N_VERSION}" N3N_VERSION)
endif()
string(TIMESTAMP N3N_BUILDDATE "%Y-%m-%d" UTC)

# What libs/connslot/file2strbufc makes of the management page's script, in
# CMake itself: no Perl needed on the machine that builds the app
function(file2strbufc input name output)
    file(READ ${input} hex HEX)
    string(LENGTH "${hex}" hexlen)
    math(EXPR size "${hexlen} / 2 + 1")
    math(EXPR wr_pos "${size} - 1")
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")
    file(WRITE ${output}
        "static strbuf_t ${name} = {\n"
        "    .capacity = ${size},\n"
        "    .wr_pos = ${wr_pos},\n"
        "    .str = { ${bytes} 0x00 }\n"
        "};\n")
endfunction()
file2strbufc(${TOP}/src/management_script.js management_script
             ${CMAKE_CURRENT_BINARY_DIR}/gen/management_script.js.h)

# The edge's sources: those of the Makefile's OBJS, less the relay role
# (RELAY_OBJS) and the devices of other systems
file(GLOB N3N_CORE
    ${TOP}/src/*.c
    ${TOP}/src/crypto/*.c
    ${TOP}/src/benchmark/*.c)
list(FILTER N3N_CORE EXCLUDE REGEX "/(role_federate|role_relay|sn_communities|sn_utils)\\.c$")
list(FILTER N3N_CORE EXCLUDE REGEX "/tuntap_(freebsd|netbsd|osx)\\.c$")
list(FILTER N3N_CORE EXCLUDE REGEX "/crypto/speck\\.c$")
list(FILTER N3N_CORE EXCLUDE REGEX "/win32/")

add_library(n3n SHARED
    ${N3N_CORE}
    ${TOP}/libs/lzo/minilzo.c
    ${TOP}/libs/connslot/connslot.c
    ${TOP}/libs/connslot/jsonrpc.c
    ${TOP}/libs/connslot/strbuf.c
    n3n_jni.c)

target_include_directories(n3n PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}             # config.h for Android
    ${CMAKE_CURRENT_BINARY_DIR}/gen         # management_script.js.h
    ${TOP}/include
    ${TOP}/libs
    ${TOP}/src)

target_compile_definitions(n3n PRIVATE
    VERSION="${N3N_VERSION}"
    BUILDDATE="${N3N_BUILDDATE}"
    CONFIG_RUNDIR="/data/local/tmp"
    METRICS)                            # as libs/connslot/Makefile builds it

target_compile_options(n3n PRIVATE -Wall -Wno-unused-function -Wno-unused-variable)

if(ANDROID)
    target_link_libraries(n3n log)
else()
    # checking the build on a Linux host, without the NDK
    find_package(JNI REQUIRED)
    target_include_directories(n3n PRIVATE ${JNI_INCLUDE_DIRS})
    target_link_libraries(n3n pthread)
endif()

# every symbol resolved when the library is built, not when it is loaded
target_link_options(n3n PRIVATE -Wl,--no-undefined)
