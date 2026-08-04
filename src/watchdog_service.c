#include <windows.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define AC_WATCHDOG_SERVICE_NAME L"AcTelemetryWatchdog"
#define AC_WATCHDOG_COMMAND_CAPACITY 32768u

typedef struct AcWatchdogServiceOptions {
    const wchar_t *python_path;
    const wchar_t *watchdog_path;
    const wchar_t *config_path;
    const wchar_t *working_directory;
    bool service_mode;
} AcWatchdogServiceOptions;

static SERVICE_STATUS_HANDLE g_status_handle = NULL;
static SERVICE_STATUS g_status;
static HANDLE g_stop_event = NULL;
static HANDLE g_job = NULL;
static PROCESS_INFORMATION g_child;
static AcWatchdogServiceOptions g_options;

static void ac_report_event(WORD type, const wchar_t *message)
{
    HANDLE source = RegisterEventSourceW(NULL, AC_WATCHDOG_SERVICE_NAME);

    if (source != NULL) {
        const wchar_t *messages[1] = {message};
        (void)ReportEventW(
            source,
            type,
            0,
            0,
            NULL,
            1,
            0,
            messages,
            NULL);
        (void)DeregisterEventSource(source);
    }
}

static void ac_set_service_status(
    DWORD state,
    DWORD win32_exit_code,
    DWORD service_exit_code,
    DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    memset(&g_status, 0, sizeof(g_status));
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32_exit_code;
    g_status.dwServiceSpecificExitCode = service_exit_code;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted =
        state == SERVICE_RUNNING
            ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            : 0;
    g_status.dwCheckPoint =
        state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING
            ? checkpoint++
            : 0;
    if (g_status_handle != NULL) {
        (void)SetServiceStatus(g_status_handle, &g_status);
    }
}

static DWORD WINAPI ac_service_control(
    DWORD control,
    DWORD event_type,
    LPVOID event_data,
    LPVOID context)
{
    (void)event_type;
    (void)event_data;
    (void)context;

    if (control == SERVICE_CONTROL_STOP ||
        control == SERVICE_CONTROL_SHUTDOWN) {
        ac_set_service_status(
            SERVICE_STOP_PENDING,
            ERROR_SUCCESS,
            ERROR_SUCCESS,
            10000u);
        if (g_stop_event != NULL) {
            (void)SetEvent(g_stop_event);
        }
        return ERROR_SUCCESS;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static bool ac_path_argument_valid(const wchar_t *value)
{
    return value != NULL && value[0] != L'\0' &&
           wcschr(value, L'"') == NULL && wcslen(value) < MAX_PATH * 4u;
}

static bool ac_build_command(wchar_t *command, size_t capacity)
{
    int written;

    if (!ac_path_argument_valid(g_options.python_path) ||
        !ac_path_argument_valid(g_options.watchdog_path) ||
        !ac_path_argument_valid(g_options.config_path) ||
        !ac_path_argument_valid(g_options.working_directory)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }
    written = _snwprintf_s(
        command,
        capacity,
        _TRUNCATE,
        L"\"%ls\" \"%ls\" --config \"%ls\"",
        g_options.python_path,
        g_options.watchdog_path,
        g_options.config_path);
    if (written < 0 || (size_t)written >= capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return false;
    }
    return true;
}

static bool ac_create_restricted_process(void)
{
    HANDLE process_token = NULL;
    HANDLE restricted_token = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    STARTUPINFOW startup;
    wchar_t *command;
    bool success = false;

    command = (wchar_t *)calloc(
        AC_WATCHDOG_COMMAND_CAPACITY,
        sizeof(*command));
    if (command == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    if (!ac_build_command(command, AC_WATCHDOG_COMMAND_CAPACITY)) {
        free(command);
        return false;
    }
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY |
                TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            &process_token) ||
        !CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE,
            0,
            NULL,
            0,
            NULL,
            0,
            NULL,
            &restricted_token)) {
        goto cleanup;
    }

    g_job = CreateJobObjectW(NULL, NULL);
    if (g_job == NULL) {
        goto cleanup;
    }
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if (!SetInformationJobObject(
            g_job,
            JobObjectExtendedLimitInformation,
            &limits,
            (DWORD)sizeof(limits))) {
        goto cleanup;
    }

    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(&g_child, 0, sizeof(g_child));
    if (!CreateProcessAsUserW(
            restricted_token,
            g_options.python_path,
            command,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            NULL,
            g_options.working_directory,
            &startup,
            &g_child) ||
        !AssignProcessToJobObject(g_job, g_child.hProcess) ||
        ResumeThread(g_child.hThread) == (DWORD)-1) {
        if (g_child.hProcess != NULL) {
            (void)TerminateProcess(g_child.hProcess, ERROR_PROCESS_ABORTED);
        }
        goto cleanup;
    }
    success = true;

cleanup:
    if (restricted_token != NULL) {
        CloseHandle(restricted_token);
    }
    if (process_token != NULL) {
        CloseHandle(process_token);
    }
    free(command);
    return success;
}

static DWORD ac_run_supervisor(void)
{
    HANDLE waits[2];
    DWORD wait_result;
    DWORD child_exit = ERROR_PROCESS_ABORTED;

    g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL || !ac_create_restricted_process()) {
        const DWORD error = GetLastError();
        ac_report_event(EVENTLOG_ERROR_TYPE, L"Cannot start restricted watchdog supervisor");
        return error != ERROR_SUCCESS ? error : ERROR_PROCESS_ABORTED;
    }

    waits[0] = g_stop_event;
    waits[1] = g_child.hProcess;
    ac_set_service_status(
        SERVICE_RUNNING,
        ERROR_SUCCESS,
        ERROR_SUCCESS,
        0);
    ac_report_event(EVENTLOG_INFORMATION_TYPE, L"Watchdog supervisor started");
    wait_result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);

    if (wait_result == WAIT_OBJECT_0) {
        ac_set_service_status(
            SERVICE_STOP_PENDING,
            ERROR_SUCCESS,
            ERROR_SUCCESS,
            10000u);
        (void)TerminateJobObject(g_job, ERROR_PROCESS_ABORTED);
        (void)WaitForSingleObject(g_child.hProcess, 10000u);
        child_exit = ERROR_SUCCESS;
    } else if (wait_result == WAIT_OBJECT_0 + 1u) {
        if (!GetExitCodeProcess(g_child.hProcess, &child_exit)) {
            child_exit = GetLastError();
        }
        ac_report_event(
            child_exit == ERROR_SUCCESS
                ? EVENTLOG_INFORMATION_TYPE
                : EVENTLOG_ERROR_TYPE,
            L"Watchdog supervisor exited");
    } else {
        child_exit = GetLastError();
        (void)TerminateJobObject(g_job, ERROR_PROCESS_ABORTED);
    }
    return child_exit;
}

static void ac_cleanup(void)
{
    if (g_child.hThread != NULL) {
        CloseHandle(g_child.hThread);
        g_child.hThread = NULL;
    }
    if (g_child.hProcess != NULL) {
        CloseHandle(g_child.hProcess);
        g_child.hProcess = NULL;
    }
    if (g_job != NULL) {
        CloseHandle(g_job);
        g_job = NULL;
    }
    if (g_stop_event != NULL) {
        CloseHandle(g_stop_event);
        g_stop_event = NULL;
    }
}

static void WINAPI ac_service_main(DWORD argc, wchar_t **argv)
{
    DWORD result;
    (void)argc;
    (void)argv;

    g_status_handle = RegisterServiceCtrlHandlerExW(
        AC_WATCHDOG_SERVICE_NAME,
        ac_service_control,
        NULL);
    if (g_status_handle == NULL) {
        return;
    }
    ac_set_service_status(
        SERVICE_START_PENDING,
        ERROR_SUCCESS,
        ERROR_SUCCESS,
        10000u);
    result = ac_run_supervisor();
    ac_cleanup();
    ac_set_service_status(
        SERVICE_STOPPED,
        result == ERROR_SUCCESS ? ERROR_SUCCESS : ERROR_SERVICE_SPECIFIC_ERROR,
        result,
        0);
}

static void ac_usage(const wchar_t *program)
{
    fwprintf(
        stdout,
        L"Usage:\n"
        L"  %ls --service --python <python.exe> --watchdog <session_watchdog.py> "
        L"--config <config.json> --working-directory <dir>\n",
        program);
}

int wmain(int argc, wchar_t **argv)
{
    SERVICE_TABLE_ENTRYW dispatch_table[] = {
        {AC_WATCHDOG_SERVICE_NAME, ac_service_main},
        {NULL, NULL}
    };
    int index;

    memset(&g_options, 0, sizeof(g_options));
    for (index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], L"--service") == 0) {
            g_options.service_mode = true;
        } else if (wcscmp(argv[index], L"--help") == 0) {
            ac_usage(argv[0]);
            return 0;
        } else if (index + 1 < argc &&
                   wcscmp(argv[index], L"--python") == 0) {
            g_options.python_path = argv[++index];
        } else if (index + 1 < argc &&
                   wcscmp(argv[index], L"--watchdog") == 0) {
            g_options.watchdog_path = argv[++index];
        } else if (index + 1 < argc &&
                   wcscmp(argv[index], L"--config") == 0) {
            g_options.config_path = argv[++index];
        } else if (index + 1 < argc &&
                   wcscmp(argv[index], L"--working-directory") == 0) {
            g_options.working_directory = argv[++index];
        } else {
            ac_usage(argv[0]);
            return 2;
        }
    }

    if (!g_options.service_mode ||
        !ac_path_argument_valid(g_options.python_path) ||
        !ac_path_argument_valid(g_options.watchdog_path) ||
        !ac_path_argument_valid(g_options.config_path) ||
        !ac_path_argument_valid(g_options.working_directory)) {
        ac_usage(argv[0]);
        return 2;
    }
    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        fwprintf(stderr, L"StartServiceCtrlDispatcher failed: %lu\n", GetLastError());
        return 3;
    }
    return 0;
}
