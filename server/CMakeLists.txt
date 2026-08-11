# keystorkd -- cross-compiled with the Android NDK.
#
#   cmake -S server -B build
#   cmake --build build -j
#
# With ANDROID_HOME and ANDROID_NDK_ROOT exported, that is the whole build:
# the SDK, the NDK, the ABI and the API level are all resolved below.
#
# The keystore2 interface declares min_sdk_version 30 for its NDK backend, but
# the daemon needs AServiceManager_waitForService, which the platform marks
# __INTRODUCED_IN(31). 31 (Android 12) is therefore the real floor. It costs
# nothing in practice: batched listing needs keystore2 V3, which is Android 14.

cmake_minimum_required(VERSION 3.22)

# ---------------------------------------------------------------------------
# Android SDK and NDK
#
# Two separate inputs, both required: the NDK cross-compiles the daemon, and
# the SDK is what Gradle builds the agent's APK with. Both must be resolved
# before project(), which is where the toolchain file is read.
# ---------------------------------------------------------------------------

# ANDROID_HOME is the name Gradle, AGP and sdkmanager all use; ANDROID_SDK_ROOT
# is its older spelling. A platforms/ subdirectory is what distinguishes a real
# SDK from a stale path.
foreach(_sdk "$ENV{ANDROID_HOME}" "$ENV{ANDROID_SDK_ROOT}")
    if(_sdk AND IS_DIRECTORY "${_sdk}/platforms")
        set(_android_sdk "${_sdk}")
        break()
    endif()
endforeach()

if(NOT _android_sdk)
    message(FATAL_ERROR
        "No Android SDK. Export ANDROID_HOME.\n"
        "The daemon needs an NDK, and the agent's dex is built by Gradle, which "
        "needs platforms/android-36 and a build-tools package:\n"
        "  sdkmanager \"ndk;29.0.14206865\" \"platforms;android-36\" \"build-tools;36.0.0\"")
endif()

# ANDROID_NDK_ROOT is the NDK's own documented variable; ANDROID_NDK_HOME and
# ANDROID_NDK are older spellings that CI images tend to set as well.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    foreach(_root "$ENV{ANDROID_NDK_ROOT}" "$ENV{ANDROID_NDK_HOME}" "$ENV{ANDROID_NDK}")
        if(_root AND EXISTS "${_root}/build/cmake/android.toolchain.cmake")
            set(CMAKE_TOOLCHAIN_FILE "${_root}/build/cmake/android.toolchain.cmake"
                CACHE FILEPATH "Android NDK toolchain file")
            message(STATUS "Using NDK at ${_root}")
            break()
        endif()
    endforeach()
endif()

if(NOT CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR
        "No NDK. Export ANDROID_NDK_ROOT, pointing at an NDK installed with\n"
        "  sdkmanager \"ndk;29.0.14206865\"\n"
        "which lands in ${_android_sdk}/ndk/<version>. Any release "
        "will do: the NDK supplies only the toolchain, bionic and libc++, "
        "since all Binder support comes from vendor/binder_ndk/.")
endif()

# The ABI is what the device is, and the API level is the floor explained above.
# Cached rather than plain set() so the toolchain file sees them.
if(NOT DEFINED ANDROID_ABI)
    set(ANDROID_ABI "arm64-v8a" CACHE STRING "Target ABI")
endif()
if(NOT DEFINED ANDROID_PLATFORM)
    set(ANDROID_PLATFORM "android-31" CACHE STRING "Minimum supported API level")
endif()
if(NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type")
endif()

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
        "keystorkd only builds for Android, but the toolchain file at\n"
        "  ${CMAKE_TOOLCHAIN_FILE}\n"
        "did not produce an Android build. Point -DCMAKE_TOOLCHAIN_FILE at an "
        "NDK's build/cmake/android.toolchain.cmake.")
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
# The generated .pb.cc must match the runtime it links against, so protoc and
# libprotobuf-lite come from one version: proto/protobuf-version.txt, which the
# agent's Gradle build and scripts/gen_proto.sh read too. 3.19 is the last
# series with no abseil dependency, so the device links one static library and
# the build cross-compiles one dependency tree.
#
# protoc is the upstream release binary rather than the host's, so the pairing
# holds by construction on any machine.
# ---------------------------------------------------------------------------

file(READ "${KEYSTORK_ROOT}/proto/protobuf-version.txt" KEYSTORK_PROTOBUF_VERSION)
string(STRIP "${KEYSTORK_PROTOBUF_VERSION}" KEYSTORK_PROTOBUF_VERSION)

set(KEYSTORK_PROTOBUF_SOURCE_DIR "" CACHE PATH
    "Local protobuf checkout to build from instead of downloading (offline builds)")
set(KEYSTORK_PROTOC "" CACHE FILEPATH
    "protoc to use instead of the pinned download (offline builds, other hosts)")

# sha256 of each upstream asset. A version bump lands here as an unknown-hash
# error rather than as a silently unverified download.
set(_protoc_sha256_3.19.6_linux-x86_64
    "f51152d0926ccf18d89e2b4e4f31c4bf16ee5f94499d379029f80ddb8304bdd0")
set(_protoc_sha256_3.19.6_linux-aarch_64
    "c1028039721e2f3fa44d138f9ac35707966c6c81ccd79a07667a4dafb8751df7")
set(_protoc_sha256_3.19.6_osx-x86_64
    "c9bb6829452d2f8ed7a589f8a6d2a31d4a07cec8d03e34277bcd60c743bc8855")

if(KEYSTORK_PROTOC)
    set(PROTOC_EXECUTABLE "${KEYSTORK_PROTOC}")
else()
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
        set(_protoc_os "linux")
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        set(_protoc_os "osx")
    endif()
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
        set(_protoc_arch "x86_64")
    elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(_protoc_arch "aarch_64")
    endif()

    set(_protoc_platform "${_protoc_os}-${_protoc_arch}")
    set(_protoc_hash "_protoc_sha256_${KEYSTORK_PROTOBUF_VERSION}_${_protoc_platform}")
    if(NOT _protoc_os OR NOT _protoc_arch OR NOT DEFINED ${_protoc_hash})
        message(FATAL_ERROR
            "No pinned protoc ${KEYSTORK_PROTOBUF_VERSION} for "
            "${CMAKE_HOST_SYSTEM_NAME}/${CMAKE_HOST_SYSTEM_PROCESSOR}. Add its "
            "sha256 above, or point -DKEYSTORK_PROTOC at a protoc of exactly "
            "that version.")
    endif()

    set(_protoc_dir "${CMAKE_CURRENT_BINARY_DIR}/protoc")
    set(PROTOC_EXECUTABLE "${_protoc_dir}/bin/protoc")
    if(NOT EXISTS "${PROTOC_EXECUTABLE}")
        set(_protoc_zip "${_protoc_dir}/protoc.zip")
        message(STATUS "Downloading protoc ${KEYSTORK_PROTOBUF_VERSION} (${_protoc_platform})")
        file(DOWNLOAD
            "https://github.com/protocolbuffers/protobuf/releases/download/v${KEYSTORK_PROTOBUF_VERSION}/protoc-${KEYSTORK_PROTOBUF_VERSION}-${_protoc_platform}.zip"
            "${_protoc_zip}"
            EXPECTED_HASH "SHA256=${${_protoc_hash}}"
            STATUS _protoc_status)
        list(GET _protoc_status 0 _protoc_status_code)
        if(NOT _protoc_status_code EQUAL 0)
            list(GET _protoc_status 1 _protoc_status_text)
            file(REMOVE "${_protoc_zip}")
            message(FATAL_ERROR
                "Could not download protoc: ${_protoc_status_text}\n"
                "Point -DKEYSTORK_PROTOC at a protoc "
                "${KEYSTORK_PROTOBUF_VERSION} to build offline.")
        endif()
        file(ARCHIVE_EXTRACT INPUT "${_protoc_zip}" DESTINATION "${_protoc_dir}")
        # The zip does not reliably carry the executable bit.
        file(CHMOD "${PROTOC_EXECUTABLE}" PERMISSIONS
             OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
             WORLD_READ WORLD_EXECUTE)
    endif()
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
# protoc runs on the host; this build is for the device.
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "" FORCE)

# protobuf 3.19 declares cmake_minimum_required(VERSION 3.1.3), which CMake 4
# refuses outright. Raise the floor for the subproject only, then put it back so
# our own policy settings are unaffected.
set(_keystork_saved_policy_min "${CMAKE_POLICY_VERSION_MINIMUM}")
set(CMAKE_POLICY_VERSION_MINIMUM 3.10)
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
# The agent's dex
#
# The Java half is an ordinary Android app under agent/apk/, built by Gradle,
# and what is taken from it is classes.dex -- which is then embedded in the
# agent, which is embedded in the daemon. Two levels of .incbin so that what
# lands on the device is still one file and the dex never touches a filesystem
# at either end.
#
# An app build rather than javac + d8 because the Java half now has a real
# dependency (the Play Integrity SDK), and resolving a dependency's transitive
# closure and dexing it is precisely what the Android build does. Nothing is
# installed: the APK is a container we open.
#
# Gradle is invoked through the wrapper checked in beside the module, so the
# version is a property of this repository rather than of whatever is on PATH
# -- which matters, since AGP 8.x cannot run on Gradle 9.6 or newer.
# ---------------------------------------------------------------------------

set(APK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/agent/apk")
set(DEX_DIR "${CMAKE_CURRENT_BINARY_DIR}/gen/dex")
set(AGENT_DEX "${DEX_DIR}/classes.dex")

# Gradle is the authority on what is up to date here, so it runs every build --
# a couple of seconds when there is nothing to do. Its inputs are the Java, the
# manifest, the build script, the keep rules and the wrapper's own version, and
# a dependency list maintained here would be one edit away from being wrong:
# stale keep rules would embed a dex missing classes the injected process needs,
# which surfaces as a runtime failure inside somebody else's app.
#
# extract_dex.cmake copies the dex out only when it differs, so an unchanged
# APK still leaves the .incbin and the link behind it alone.
add_custom_target(agent_dex ALL
    COMMAND "${CMAKE_COMMAND}" -E env "ANDROID_HOME=${_android_sdk}"
            "${APK_DIR}/gradlew" --project-dir "${APK_DIR}" --quiet assembleRelease
    COMMAND "${CMAKE_COMMAND}" "-DAPK_DIR=${APK_DIR}" "-DOUTPUT=${AGENT_DEX}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/extract_dex.cmake"
    BYPRODUCTS "${AGENT_DEX}"
    COMMENT "building the agent's APK and taking its dex"
    VERBATIM)

set(DEX_BLOB "${CMAKE_CURRENT_BINARY_DIR}/gen/dex_blob.S")
add_custom_command(
    OUTPUT "${DEX_BLOB}"
    COMMAND "${CMAKE_COMMAND}" "-DBLOB=${AGENT_DEX}" "-DSYMBOL=kKeystorkDex"
            "-DOUTPUT=${DEX_BLOB}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_blob.cmake"
    DEPENDS "${AGENT_DEX}" agent_dex
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_blob.cmake"
    COMMENT "embedding the dex into the agent"
    VERBATIM)

# ---------------------------------------------------------------------------
# The injected agent
#
# Built for the same ABI as the daemon, then embedded in it. Nothing is ever
# pushed to the device but keystorkd itself: the agent reaches the target
# through a memfd, so it needs no path, no filesystem access, and no SELinux
# label of its own.
# ---------------------------------------------------------------------------

add_library(keystork_agent SHARED agent/agent.c "${DEX_BLOB}")
set_target_properties(keystork_agent PROPERTIES OUTPUT_NAME keystork-agent)
target_compile_options(keystork_agent PRIVATE -Wall -Wextra -fvisibility=hidden)
# -s here rather than a POST_BUILD strip: what gets embedded is whatever the
# link produced, so the shrinking has to happen during it.
target_link_options(keystork_agent PRIVATE -s -Wl,--exclude-libs,ALL)
target_link_libraries(keystork_agent PRIVATE log)

set(AGENT_BLOB "${CMAKE_CURRENT_BINARY_DIR}/gen/agent_blob.S")
add_custom_command(
    OUTPUT "${AGENT_BLOB}"
    COMMAND "${CMAKE_COMMAND}" "-DBLOB=$<TARGET_FILE:keystork_agent>"
            "-DSYMBOL=kKeystorkAgent" "-DOUTPUT=${AGENT_BLOB}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_blob.cmake"
    DEPENDS keystork_agent "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_blob.cmake"
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
