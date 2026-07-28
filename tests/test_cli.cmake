if(NOT DEFINED AC_EXECUTABLE OR NOT EXISTS "${AC_EXECUTABLE}")
    message(FATAL_ERROR "AC_EXECUTABLE must name the built collector")
endif()

if(NOT DEFINED AC_WORKING_DIRECTORY)
    message(FATAL_ERROR "AC_WORKING_DIRECTORY must be provided")
endif()

file(REMOVE_RECURSE "${AC_WORKING_DIRECTORY}")
file(MAKE_DIRECTORY "${AC_WORKING_DIRECTORY}")

execute_process(
    COMMAND "${AC_EXECUTABLE}" --version
    WORKING_DIRECTORY "${AC_WORKING_DIRECTORY}"
    RESULT_VARIABLE version_result
    OUTPUT_VARIABLE version_stdout
    ERROR_VARIABLE version_stderr
)

if(NOT version_result EQUAL 0)
    message(FATAL_ERROR "--version exited with ${version_result}: ${version_stderr}")
endif()

if(NOT version_stderr STREQUAL "")
    message(FATAL_ERROR "--version wrote to stderr: ${version_stderr}")
endif()

string(REPLACE "\r\n" "\n" version_stdout "${version_stdout}")
string(REPLACE "\r" "\n" version_stdout "${version_stdout}")
string(REGEX MATCHALL "[^\n]+" version_lines "${version_stdout}")
list(LENGTH version_lines version_line_count)

if(NOT version_line_count EQUAL 3)
    message(FATAL_ERROR "--version must emit exactly three lines: ${version_stdout}")
endif()

list(GET version_lines 0 collector_line)
list(GET version_lines 1 schema_line)
list(GET version_lines 2 protocol_line)

if(NOT collector_line MATCHES "^collector_version=[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "invalid collector version line: ${collector_line}")
endif()
if(NOT schema_line MATCHES "^event_schema_version=[0-9]+$")
    message(FATAL_ERROR "invalid event schema version line: ${schema_line}")
endif()
if(NOT protocol_line MATCHES "^driver_protocol_version=[0-9]+$")
    message(FATAL_ERROR "invalid driver protocol version line: ${protocol_line}")
endif()

if(EXISTS "${AC_WORKING_DIRECTORY}/anticheat-events.jsonl")
    message(FATAL_ERROR "--version created the default log file")
endif()

execute_process(
    COMMAND
        "${AC_EXECUTABLE}"
        --version
        --pid
        1
        --log
        version-conflict.jsonl
    WORKING_DIRECTORY "${AC_WORKING_DIRECTORY}"
    RESULT_VARIABLE conflict_result
    OUTPUT_VARIABLE conflict_stdout
    ERROR_VARIABLE conflict_stderr
)

if(NOT conflict_result EQUAL 2)
    message(FATAL_ERROR
        "conflicting --version options must exit with 2, got ${conflict_result}")
endif()
if(NOT conflict_stdout MATCHES "Usage:")
    message(FATAL_ERROR "argument error did not print usage")
endif()
if(EXISTS "${AC_WORKING_DIRECTORY}/version-conflict.jsonl")
    message(FATAL_ERROR "conflicting --version options created a log file")
endif()

execute_process(
    COMMAND "${AC_EXECUTABLE}" --help
    WORKING_DIRECTORY "${AC_WORKING_DIRECTORY}"
    RESULT_VARIABLE help_result
    OUTPUT_VARIABLE help_stdout
    ERROR_VARIABLE help_stderr
)

if(NOT help_result EQUAL 0)
    message(FATAL_ERROR "--help exited with ${help_result}: ${help_stderr}")
endif()
if(NOT help_stdout MATCHES "--version")
    message(FATAL_ERROR "--help does not document --version")
endif()
if(EXISTS "${AC_WORKING_DIRECTORY}/anticheat-events.jsonl")
    message(FATAL_ERROR "--help created the default log file")
endif()
