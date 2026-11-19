#include "service.h"
#include <windows.h>

static SERVICE_STATUS        g_svc_status = {0};
static SERVICE_STATUS_HANDLE g_svc_handle = NULL;
static DpiEngine            *g_svc_engine = NULL;

static void report_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;
    g_svc_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState     = state;
    g_svc_status.dwWin32ExitCode    = exit_code;
    g_svc_status.dwWaitHint         = wait_hint;

    if (state == SERVICE_START_PENDING) {
        g_svc_status.dwControlsAccepted = 0;
    } else {
        g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        g_svc_status.dwCheckPoint = 0;
    } else {
        g_svc_status.dwCheckPoint = checkpoint++;
    }

    if (g_svc_handle) {
        SetServiceStatus(g_svc_handle, &g_svc_status);
    }
}

static void WINAPI service_ctrl_handler(DWORD ctrl) {
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        if (g_svc_engine) {
            dpi_engine_request_stop(g_svc_engine);
        }
        break;
    case SERVICE_CONTROL_INTERROGATE:
        report_status(g_svc_status.dwCurrentState, NO_ERROR, 0);
        break;
    default:
        break;
    }
}

static void WINAPI service_main(DWORD argc, LPSTR *argv) {
    (void)argc;
    (void)argv;

    g_svc_handle = RegisterServiceCtrlHandlerA(JAPONDPI_SERVICE_NAME, service_ctrl_handler);
    if (!g_svc_handle) return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    char err_buf[512];
    if (!wd_load_library(err_buf, sizeof(err_buf))) {
        report_status(SERVICE_STOPPED, ERROR_MOD_NOT_FOUND, 0);
        return;
    }

    report_status(SERVICE_RUNNING, NO_ERROR, 0);
    int rc = dpi_engine_run(g_svc_engine);
    dpi_engine_destroy(g_svc_engine);
    wd_unload_library();

    report_status(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

int japondpi_run_as_service(DpiEngine *eng) {
    g_svc_engine = eng;
    SERVICE_TABLE_ENTRYA table[] = {
        { (LPSTR)JAPONDPI_SERVICE_NAME, service_main },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(table)) {
        return 1;
    }
    return 0;
}
