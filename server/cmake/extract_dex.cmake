# Takes classes.dex out of the APK Gradle just built.
#
#   cmake -DAPK_DIR=<module dir> -DOUTPUT=<file> -P extract_dex.cmake
#
# The APK is found by glob rather than by name: the file is named after the
# Gradle project and the build type, and neither is worth encoding here twice.

if(NOT DEFINED APK_DIR OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "extract_dex.cmake needs -DAPK_DIR and -DOUTPUT")
endif()

file(GLOB APKS "${APK_DIR}/build/outputs/apk/release/*.apk")
list(LENGTH APKS FOUND)
if(NOT FOUND EQUAL 1)
    message(FATAL_ERROR
        "expected exactly one APK in ${APK_DIR}/build/outputs/apk/release, found ${FOUND}")
endif()
list(GET APKS 0 APK)

# A second dex would mean the Java half has outgrown one, which is allowed --
# InMemoryDexClassLoader takes a ByteBuffer[] -- but is not implemented, and
# silently embedding only the first would fail much later as a missing class.
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar tf "${APK}"
    OUTPUT_VARIABLE LISTING
    RESULT_VARIABLE LISTED)
if(NOT LISTED EQUAL 0)
    message(FATAL_ERROR "could not list ${APK}")
endif()
if(LISTING MATCHES "classes2\\.dex")
    message(FATAL_ERROR
        "${APK} is multidex. The agent embeds and loads a single dex; both ends "
        "need to grow an array before this can work.")
endif()

set(STAGE "${CMAKE_CURRENT_BINARY_DIR}/extract_dex")
file(REMOVE_RECURSE "${STAGE}")
file(MAKE_DIRECTORY "${STAGE}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar xf "${APK}" -- classes.dex
    WORKING_DIRECTORY "${STAGE}"
    RESULT_VARIABLE EXTRACTED)
if(NOT EXTRACTED EQUAL 0)
    message(FATAL_ERROR "could not extract classes.dex from ${APK}")
endif()

# copy_if_different so an unchanged dex does not retrigger the .incbin and the
# link behind it.
execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${STAGE}/classes.dex" "${OUTPUT}")
