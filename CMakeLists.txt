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
    src/pe.c
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

    set(AC_PORTABLE_TEST_CASES
        sha256_vectors
        sha256_streaming
        json_escaping
        fnv1a
        range_index
        range_index_merges_overlaps
        range_index_many_entries
        dedup_suppresses_repeats
        dedup_zero_interval
        dedup_saturation
        pe_parse_valid
        pe_materialize_rebase
        pe_mask_imports
        pe_iat_slots
        pe_malformed_bounds
        pe_rejects_non_pe
        pe_relocation_bounds
    )
    foreach(test_case IN LISTS AC_PORTABLE_TEST_CASES)
        add_test(
            NAME "portable.${test_case}"
            COMMAND anticheat_portable_tests "${test_case}"
        )
        set_tests_properties(
            "portable.${test_case}"
            PROPERTIES LABELS "portable" TIMEOUT 30
        )
    endforeach()

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME transport.remote_anchoring
            COMMAND
                ${Python3_EXECUTABLE}
                -m unittest -v tests/test_transport.py
        )
        set_tests_properties(
            transport.remote_anchoring
            PROPERTIES
                LABELS "transport;integration"
                TIMEOUT 60
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                ENVIRONMENT
                    "PYTHONDONTWRITEBYTECODE=1;PYTHONWARNINGS=error::ResourceWarning"
        )
    endif()
endif()

install(
    PROGRAMS
        tools/reference_receiver.py
        tools/telemetry_shipper.py
        tools/transport_common.py
        tools/verify_log.py
    DESTINATION tools
)
install(
    FILES docs/transport-integration.md
    DESTINATION docs
)

if(APPLE)
    add_executable(anticheat src/macos_main.c)
    target_link_libraries(anticheat PRIVATE anticheat_portable)
    target_compile_features(anticheat PRIVATE c_std_11)
    ac_enable_warnings(anticheat)

    if(BUILD_TESTING)
        set(AC_MACOS_CLI_TEST_CASES version version_conflict help)
        foreach(test_case IN LISTS AC_MACOS_CLI_TEST_CASES)
            add_test(
                NAME "macos.cli.${test_case}"
                COMMAND
                    ${CMAKE_COMMAND}
                    "-DAC_CASE=${test_case}"
                    "-DAC_EXECUTABLE=$<TARGET_FILE:anticheat>"
                    "-DAC_WORKING_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/macos-cli/${test_case}"
                    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.cmake"
            )
            set_tests_properties(
                "macos.cli.${test_case}"
                PROPERTIES LABELS "cli;macos" TIMEOUT 30
            )
        endforeach()

        add_test(
            NAME macos.live_self_scan
            COMMAND
                ${CMAKE_COMMAND}
                "-DAC_EXECUTABLE=$<TARGET_FILE:anticheat>"
                "-DAC_LOG_PATH=${CMAKE_CURRENT_BINARY_DIR}/macos-self-scan.jsonl"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_macos_smoke.cmake"
        )
        set_tests_properties(
            macos.live_self_scan
            PROPERTIES LABELS "macos;integration" TIMEOUT 30
        )
    endif()

    install(TARGETS anticheat RUNTIME DESTINATION bin)
    return()
endif()

if(NOT WIN32)
    message(STATUS
        "Non-Windows host: building the portable core and its tests only. "
        "The sensor itself targets the Windows API and must be built on Windows.")
    return()
endif()

add_library(anticheat_core STATIC
    src/integrity.c
    src/kernel_client.c
    src/log.c
    src/process.c
    src/scanner.c
)
target_include_directories(anticheat_core PUBLIC src include)
target_link_libraries(anticheat_core PUBLIC anticheat_portable bcrypt)
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
if(MINGW)
    target_link_options(anticheat PRIVATE -municode)
endif()
ac_enable_warnings(anticheat)

if(BUILD_TESTING)
    add_executable(anticheat_tests tests/test_core.c)
    target_link_libraries(anticheat_tests PRIVATE anticheat_core)
    ac_enable_warnings(anticheat_tests)

    set(AC_CORE_TEST_CASES
        path_boundaries
        allow_roots
        module_list_and_ranges
        parent_directory
        image_name_matching
        wide_to_utf8
        log_chain
        log_rotation
        policy_defaults
        least_privilege_process_access
        self_scan
        integrity_clean_process
        integrity_patched_text
        integrity_module_identity
        integrity_budget_gap
        driver_protocol_session
    )
    foreach(test_case IN LISTS AC_CORE_TEST_CASES)
        add_test(
            NAME "core.${test_case}"
            COMMAND anticheat_tests "${test_case}"
        )
        set_tests_properties(
            "core.${test_case}"
            PROPERTIES LABELS "core;windows" TIMEOUT 90
        )
    endforeach()

    set(AC_CLI_TEST_CASES version version_conflict help)
    foreach(test_case IN LISTS AC_CLI_TEST_CASES)
        add_test(
            NAME "cli.${test_case}"
            COMMAND
                ${CMAKE_COMMAND}
                "-DAC_CASE=${test_case}"
                "-DAC_EXECUTABLE=$<TARGET_FILE:anticheat>"
                "-DAC_WORKING_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/cli-contract/${test_case}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.cmake"
        )
        set_tests_properties(
            "cli.${test_case}"
            PROPERTIES LABELS "cli;windows" TIMEOUT 30
        )
    endforeach()
endif()

install(TARGETS anticheat RUNTIME DESTINATION bin)
