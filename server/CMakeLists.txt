# keystorkd -- cross-compiled with the Android NDK.
#
#   cmake -S server -B build \
#         -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-31 \
#         -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#
# The keystore2 interface declares min_sdk_version 30 for its NDK backend, but
# the daemon needs AServiceManager_waitForService, which the platform marks
# __INTRODUCED_IN(31). 31 (Android 12) is therefore the real floor. It costs
# nothing in practice: batched listing needs keystore2 V3, which is Android 14.

cmake_minimum_required(VERSION 3.22)

# Everything we ship is linked statically, so what lands on the device is a
# single self-contained binary with no libc++_shared.so to push alongside it.
# Full static is not an option and not the goal: the daemon must dynamically
# link the device's own libbinder_ndk.so, liblog.so and bionic, which is the
# entire point of speaking the platform's stable Binder ABI. Must be set before
# project(), which is where the NDK toolchain file is processed.
if(NOT DEFINED ANDROID_STL)
    set(ANDROID_STL "c++_static" CACHE STRING "Android C++ runtime")
endif()

# ASM is for the generated stub that .incbin's the agent into .rodata.
project(keystorkd LANGUAGES C CXX ASM)

if(NOT ANDROID)
    message(FATAL_ERROR
        "keystorkd only builds for Android. Pass the NDK toolchain file:\n"
        "  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake "
        "-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30")
endif()

if(NOT ANDROID_STL STREQUAL "c++_static")
    message(WARNING
        "ANDROID_STL is '${ANDROID_STL}'. The daemon is meant to be a single "
        "self-contained binary; with a shared STL you must also push libc++_shared.so.")
endif()

# The NDK's Binder support is not used at all: its headers are older than the
# AIDL generator that produced the vendored stubs (and r28+ drops the C++ ones
# entirely), and its libbinder_ndk.so exports only part of the library. Both
# come from vendor/binder_ndk/ instead, at the same AOSP tag as the stubs, so
# the NDK supplies only the toolchain, bionic and libc++.

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Let the linker drop the large unused parts of the AIDL stubs and of
# protobuf-lite; only a fraction of either is reachable from `list`.
add_compile_options(-ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections)

get_filename_component(KEYSTORK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

# ---------------------------------------------------------------------------
# libbinder_ndk
#
# The NDK's libbinder_ndk.so exports only part of the library: none of
# AServiceManager_*, ABinderProcess_*, or AParcel_markSensitive, at any API
# level. Rather than hand-maintaining a list of the gaps, the link stub is
# generated from AOSP's own version script (vendor/binder_ndk/libbinder_ndk.map.txt)
# so every symbol the device exports resolves at link time. The stub carries
# SONAME libbinder_ndk.so, so the executable gets one DT_NEEDED entry and the
# device's real library backs it at runtime. The stub itself is never pushed.
# ---------------------------------------------------------------------------

set(BINDER_NDK_MAP "${KEYSTORK_ROOT}/vendor/binder_ndk/libbinder_ndk.map.txt")
set(BINDER_NDK_STUB_SRC "${CMAKE_CURRENT_BINARY_DIR}/gen/binder_ndk_stub.c")

add_custom_command(
    OUTPUT "${BINDER_NDK_STUB_SRC}"
    COMMAND "${CMAKE_COMMAND}"
            -DMAP=${BINDER_NDK_MAP} -DOUT=${BINDER_NDK_STUB_SRC}
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_binder_ndk_stub.cmake"
    DEPENDS "${BINDER_NDK_MAP}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_binder_ndk_stub.cmake"
    COMMENT "generating libbinder_ndk link stub from AOSP version script"
    VERBATIM)

add_library(binder_ndk_stub SHARED "${BINDER_NDK_STUB_SRC}")
target_compile_options(binder_ndk_stub PRIVATE -w -fno-stack-protector)
target_link_options(binder_ndk_stub PRIVATE "-nostdlib")

# The output must be *named* libbinder_ndk.so rather than having -soname forced
# onto the link line: CMake emits its own -soname from the target name after any
# manual flag, and the last one wins. Getting this wrong is silent -- the binary
# links fine and then fails to load on the device, looking for a library that
# only ever existed on the build host. Staged in its own directory so nothing
# mistakes it for something to push.
set_target_properties(binder_ndk_stub PROPERTIES
    OUTPUT_NAME binder_ndk
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/linkstub")

# The vendored AOSP headers must precede the NDK sysroot's older copies: the
# generated AIDL stubs are emitted by the same AOSP tag and use binder APIs the
# NDK's headers predate. BEFORE + plain -I beats the sysroot's -isystem.
add_library(binder_ndk_headers INTERFACE)
target_include_directories(binder_ndk_headers BEFORE INTERFACE
    "${KEYSTORK_ROOT}/vendor/binder_ndk/include_ndk"
    "${KEYSTORK_ROOT}/vendor/binder_ndk/include_cpp"
    "${KEYSTORK_ROOT}/vendor/binder_ndk/include_platform")
target_link_libraries(binder_ndk_headers INTERFACE binder_ndk_stub)

# ---------------------------------------------------------------------------
# protobuf
#
# The generated .pb.cc must match the runtime it links against, so protoc on the
# host and libprotobuf-lite for the device are pinned to the same version. 3.19
# is the last series with no abseil dependency, which keeps the device-side
# build to a single small static library.
# ---------------------------------------------------------------------------

set(KEYSTORK_PROTOBUF_VERSION "3.19.6" CACHE STRING
    "protobuf version to build libprotobuf-lite from")
set(KEYSTORK_PROTOBUF_SOURCE_DIR "" CACHE PATH
    "Local protobuf checkout to build from instead of downloading (offline builds)")

find_program(PROTOC_EXECUTABLE protoc)
if(NOT PROTOC_EXECUTABLE)
    message(FATAL_ERROR "protoc not found (dnf install protobuf-compiler)")
endif()

execute_process(COMMAND "${PROTOC_EXECUTABLE}" --version
                OUTPUT_VARIABLE PROTOC_VERSION_OUTPUT
                OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" PROTOC_VERSION "${PROTOC_VERSION_OUTPUT}")
if(NOT PROTOC_VERSION VERSION_EQUAL KEYSTORK_PROTOBUF_VERSION)
    # A mismatched generator and runtime fail at compile time with an opaque
    # static assert, so it is caught here instead.
    message(FATAL_ERROR
        "protoc is ${PROTOC_VERSION} but the runtime is pinned to ${KEYSTORK_PROTOBUF_VERSION}.\n"
        "Install a matching protoc, or set -DKEYSTORK_PROTOBUF_VERSION=${PROTOC_VERSION}.")
endif()

include(FetchContent)
if(KEYSTORK_PROTOBUF_SOURCE_DIR)
    FetchContent_Declare(protobuf
        SOURCE_DIR "${KEYSTORK_PROTOBUF_SOURCE_DIR}"
        SOURCE_SUBDIR cmake)
else()
    FetchContent_Declare(protobuf
        GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
        GIT_TAG        v${KEYSTORK_PROTOBUF_VERSION}
        GIT_SHALLOW    TRUE
        SOURCE_SUBDIR  cmake)
endif()

set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
# protoc comes from the host; cross-building it here would be pointless.
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "" FORCE)

# protobuf 3.19 declares cmake_minimum_required(VERSION 3.1.3), which CMake 4
# refuses outright. Raise the floor for the subproject only, then put it back so
# our own policy settings are unaffected.
set(_keystork_saved_policy_min "${CMAKE_POLICY_VERSION_MINIMUM}")
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
FetchContent_MakeAvailable(protobuf)
set(CMAKE_POLICY_VERSION_MINIMUM "${_keystork_saved_policy_min}")

# ---------------------------------------------------------------------------
# Generated wire protocol
# ---------------------------------------------------------------------------

set(PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen")
set(PROTO_SRC "${PROTO_GEN_DIR}/keystork.pb.cc")
set(PROTO_HDR "${PROTO_GEN_DIR}/keystork.pb.h")

file(MAKE_DIRECTORY "${PROTO_GEN_DIR}")
add_custom_command(
    OUTPUT "${PROTO_SRC}" "${PROTO_HDR}"
    COMMAND "${PROTOC_EXECUTABLE}"
            --proto_path=${KEYSTORK_ROOT}/proto
            --cpp_out=${PROTO_GEN_DIR}
            ${KEYSTORK_ROOT}/proto/keystork.proto
    DEPENDS "${KEYSTORK_ROOT}/proto/keystork.proto"
    COMMENT "protoc keystork.proto (C++)"
    VERBATIM)

# ---------------------------------------------------------------------------
# Vendored AIDL stubs
#
# Generated by Soong from a real AOSP tree and committed under vendor/; see
# vendor/README.md. Compiled as-is with warnings off, because they are generator
# output and must never be hand-edited to silence anything.
# ---------------------------------------------------------------------------

set(AIDL_MODULES
    android.system.keystore2-V6-ndk
    android.hardware.security.keymint-V5-ndk
    android.hardware.security.secureclock-V1-ndk)

set(AIDL_SOURCES "")
set(AIDL_INCLUDE_DIRS "")
foreach(module IN LISTS AIDL_MODULES)
    set(module_dir "${KEYSTORK_ROOT}/vendor/aidl/${module}")
    if(NOT EXISTS "${module_dir}")
        message(FATAL_ERROR "missing vendored AIDL stubs: ${module_dir}")
    endif()
    file(GLOB_RECURSE module_sources CONFIGURE_DEPENDS "${module_dir}/android/*.cpp")
    list(APPEND AIDL_SOURCES ${module_sources})
    list(APPEND AIDL_INCLUDE_DIRS "${module_dir}/include")
endforeach()

add_library(keystore_aidl STATIC ${AIDL_SOURCES})
target_include_directories(keystore_aidl PUBLIC ${AIDL_INCLUDE_DIRS})
target_link_libraries(keystore_aidl PUBLIC binder_ndk_headers)
target_compile_options(keystore_aidl PRIVATE -w)

# ---------------------------------------------------------------------------
# The injected agent
#
# Built for the same ABI as the daemon, then embedded in it. Nothing is ever
# pushed to the device but keystorkd itself: the agent reaches the target
# through a memfd, so it needs no path, no filesystem access, and no SELinux
# label of its own.
# ---------------------------------------------------------------------------

add_library(keystork_agent SHARED agent/agent.c)
set_target_properties(keystork_agent PROPERTIES OUTPUT_NAME keystork-agent)
target_compile_options(keystork_agent PRIVATE -Wall -Wextra -fvisibility=hidden)
# -s here rather than a POST_BUILD strip: what gets embedded is whatever the
# link produced, so the shrinking has to happen during it.
target_link_options(keystork_agent PRIVATE -s -Wl,--exclude-libs,ALL)
target_link_libraries(keystork_agent PRIVATE log)

set(AGENT_BLOB "${CMAKE_CURRENT_BINARY_DIR}/gen/agent_blob.S")
add_custom_command(
    OUTPUT "${AGENT_BLOB}"
    COMMAND "${CMAKE_COMMAND}"
            "-DAGENT=$<TARGET_FILE:keystork_agent>"
            "-DOUTPUT=${AGENT_BLOB}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_agent.cmake"
    DEPENDS keystork_agent "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_agent.cmake"
    COMMENT "embedding $<TARGET_FILE_NAME:keystork_agent> into the daemon"
    VERBATIM)

# ---------------------------------------------------------------------------
# keystorkd
# ---------------------------------------------------------------------------

add_executable(keystorkd
    src/main.cpp
    src/exec.cpp
    src/framing.cpp
    src/inject.cpp
    src/session.cpp
    src/status.cpp
    src/tracee.cpp
    "${AGENT_BLOB}"
    "${PROTO_SRC}")

target_include_directories(keystorkd PRIVATE src "${PROTO_GEN_DIR}")
target_compile_options(keystorkd PRIVATE -Wall -Wextra)
target_link_libraries(keystorkd PRIVATE keystore_aidl binder_ndk_headers protobuf::libprotobuf-lite log)

# With c++_static there is nothing to ship beside the binary. Report what it
# will actually need from the device, so a surprise dependency is visible at
# build time rather than as a dynamic-linker failure on the phone.
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_STRIP)
    add_custom_command(TARGET keystorkd POST_BUILD
        COMMAND "${CMAKE_STRIP}" --strip-all "$<TARGET_FILE:keystorkd>"
        COMMENT "stripping keystorkd")
endif()

add_custom_command(TARGET keystorkd POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E echo "keystorkd needs these from the device:"
    COMMAND "${CMAKE_READELF}" -d "$<TARGET_FILE:keystorkd>" | grep NEEDED || true
    VERBATIM)
