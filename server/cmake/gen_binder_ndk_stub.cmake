# Generates a C source file defining every symbol libbinder_ndk exports.
#
#   cmake -DMAP=<libbinder_ndk.map.txt> -DOUT=<stub.c> -P gen_binder_ndk_stub.cmake
#
# The result is compiled into a shared library with SONAME libbinder_ndk.so and
# used only to satisfy the linker; the device's real library provides the
# implementations. Deriving it from AOSP's own version script means a symbol
# that exists on the device can never be missing at link time -- which is the
# failure the NDK's partial libbinder_ndk.so stub produces, since it exports
# none of AServiceManager_*, ABinderProcess_*, or AParcel_markSensitive.
#
# Signatures are irrelevant: ELF linking matches on name alone, and every caller
# sees the real declarations from the vendored headers.

file(READ "${MAP}" _map)

# Every exported name in the map begins with 'A' (AIBinder_, AParcel_,
# AServiceManager_, ABinderProcess_, AStatus_, ...) and sits alone on its own
# indented line, so anchoring to the line start skips the `local: *;` entries,
# the version-block headers, and any prose in trailing comments.
#
# MATCHALL returns a ;-separated list and each match itself ends in ';', so
# every match is followed by an empty element -- hence the REMOVE_ITEM below.
string(REGEX MATCHALL "\n[ \t]+A[A-Za-z0-9_]+;" _entries "${_map}")
list(REMOVE_ITEM _entries "")

set(_symbols "")
foreach(_entry IN LISTS _entries)
    string(REGEX REPLACE "[\n \t]+" "" _symbol "${_entry}")
    string(REGEX REPLACE ";" "" _symbol "${_symbol}")
    if(_symbol)
        list(APPEND _symbols "${_symbol}")
    endif()
endforeach()
list(REMOVE_DUPLICATES _symbols)
list(SORT _symbols)

list(LENGTH _symbols _count)
set(_out "/*\n * Generated from ${MAP} -- do not edit.\n")
string(APPEND _out " * ${_count} link-time placeholders for libbinder_ndk.\n */\n\n")
foreach(_symbol IN LISTS _symbols)
    string(APPEND _out "void ${_symbol}(void) {}\n")
endforeach()

file(WRITE "${OUT}" "${_out}")
message(STATUS "generated ${_count} libbinder_ndk link stubs")
