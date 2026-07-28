cmake_minimum_required(VERSION 3.24)

project(anticheat_telemetry VERSION 0.3.0 LANGUAGES C)

function(ac_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

# Portable core: hashing, escaping, range index and event de-duplication.
# It has no Windows dependency so the logic can be built and tested anywhere.
add_library(anticheat_portable STATIC
    src/dedup.c
    src/ranges.c
    src/sha256.c
    src/text.c
)
target_include_directories(anticheat_portable PUBLIC src)
target_compile_features(anticheat_portable PUBLIC c_std_11)
ac_enable_warnings(anticheat_portable)

include(CTest)
if(BUILD_TESTING)
    add_executable(anticheat_portable_tests tests/test_portable.c)
    target_link_libraries(anticheat_portable_tests PRIVATE anticheat_portable)
    ac_enable_warnings(anticheat_portable_tests)
    add_test(NAME anticheat_portable_tests COMMAND anticheat_portable_tests)
endif()

if(NOT WIN32)
    message(STATUS
        "Non-Windows host: building the portable core and its tests only. "
        "The sensor itself targets the Windows API and must be built on Windows.")
    return()
endif()

add_library(anticheat_core STATIC
    src/kernel_client.c
    src/log.c
    src/process.c
    src/scanner.c
)
target_include_directories(anticheat_core PUBLIC src include)
target_link_libraries(anticheat_core PUBLIC anticheat_portable)
target_compile_definitions(anticheat_core PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=0x0601
)
ac_enable_warnings(anticheat_core)

add_executable(anticheat src/main.c)
target_link_libraries(anticheat PRIVATE anticheat_core)
ac_enable_warnings(anticheat)

if(BUILD_TESTING)
    add_executable(anticheat_tests tests/test_core.c)
    target_link_libraries(anticheat_tests PRIVATE anticheat_core)
    ac_enable_warnings(anticheat_tests)
    add_test(NAME anticheat_core_tests COMMAND anticheat_tests)

    add_test(
        NAME anticheat_cli_contract
        COMMAND
            ${CMAKE_COMMAND}
            "-DAC_EXECUTABLE=$<TARGET_FILE:anticheat>"
            "-DAC_WORKING_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-contract"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.cmake"
    )
endif()

install(TARGETS anticheat RUNTIME DESTINATION bin)
