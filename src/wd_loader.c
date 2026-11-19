#include "wd_loader.h"
#include <stdio.h>
#include <wchar.h>

WinDivertAPI g_wd = {0};

bool get_exe_dir_w(wchar_t *buf, DWORD buf_chars) {
    DWORD len = GetModuleFileNameW(NULL, buf, buf_chars);
    if (len == 0 || len >= buf_chars) {
        return false;
    }
    wchar_t *slash = wcsrchr(buf, L'\\');
    if (!slash) {
        return false;
    }
    *slash = L'\0';
    return true;
}

bool wd_load_library(char *err_buf, size_t err_buf_len) {
    if (g_wd.module != NULL) {
        return true;
    }

    wchar_t exe_dir[MAX_PATH];
    wchar_t dll_path[MAX_PATH];
    wchar_t sys_path[MAX_PATH];

    if (!get_exe_dir_w(exe_dir, MAX_PATH)) {
        snprintf(err_buf, err_buf_len, "Calistirilabilir dosya konumu belirlenemedi.");
        return false;
    }

    /* Ensure DLL & driver search includes exe directory (critical for Windows Service mode) */
    SetDllDirectoryW(exe_dir);
    SetCurrentDirectoryW(exe_dir);

    _snwprintf(dll_path, MAX_PATH, L"%ls\\WinDivert.dll", exe_dir);
    dll_path[MAX_PATH - 1] = L'\0';
    _snwprintf(sys_path, MAX_PATH, L"%ls\\WinDivert64.sys", exe_dir);
    sys_path[MAX_PATH - 1] = L'\0';

    DWORD dll_attr = GetFileAttributesW(dll_path);
    DWORD sys_attr = GetFileAttributesW(sys_path);

    if (dll_attr == INVALID_FILE_ATTRIBUTES || sys_attr == INVALID_FILE_ATTRIBUTES) {
        snprintf(err_buf, err_buf_len,
            "WinDivert.dll veya WinDivert64.sys bulunamadi!\n"
            "Lutfen resmi WinDivert 2.2.0-C paketini GitHub'dan indirip\n"
            "(https://github.com/basil00/WinDivert/releases/tag/v2.2.0)\n"
            "x64 klasorundeki 'WinDivert.dll' ve 'WinDivert64.sys' dosyalarini\n"
            "japondpi.exe ile ayni klasore (x86_64) kopyalayin.");
        return false;
    }

    HMODULE hMod = LoadLibraryW(dll_path);
    if (!hMod) {
        DWORD err = GetLastError();
        if (err == ERROR_VIRUS_INFECTED || err == ERROR_VIRUS_DELETED) {
            snprintf(err_buf, err_buf_len,
                "Windows Defender / Antivirus WinDivert.dll dosyasini engelledi (Kod: %lu).\n"
                "WinDivert acik kaynakli, Microsoft WHQL imzali resmi ag surucusudur.\n"
                "Kullanmak icin Japon DPI klasorunu Windows Guvenligi Dislamalarina ekleyin.",
                (unsigned long)err);
        } else {
            snprintf(err_buf, err_buf_len,
                "WinDivert.dll yuklenemedi (Windows Hata Kodu: %lu).",
                (unsigned long)err);
        }
        return false;
    }

#define LOAD_SYM(field, name) do { \
    g_wd.field = (pfn_##name)(void *)GetProcAddress(hMod, #name); \
    if (!g_wd.field) { \
        FreeLibrary(hMod); \
        ZeroMemory(&g_wd, sizeof(g_wd)); \
        snprintf(err_buf, err_buf_len, "WinDivert.dll icinde '%s' fonksiyonu bulunamadi (Surum 2.2+ gerekli).", #name); \
        return false; \
    } \
} while (0)

    LOAD_SYM(Open,                WinDivertOpen);
    LOAD_SYM(Recv,                WinDivertRecv);
    LOAD_SYM(Send,                WinDivertSend);
    LOAD_SYM(Shutdown,            WinDivertShutdown);
    LOAD_SYM(Close,               WinDivertClose);
    LOAD_SYM(SetParam,            WinDivertSetParam);
    LOAD_SYM(GetParam,            WinDivertGetParam);
    LOAD_SYM(HelperParsePacket,   WinDivertHelperParsePacket);
    LOAD_SYM(HelperCalcChecksums, WinDivertHelperCalcChecksums);
    LOAD_SYM(HelperCompileFilter, WinDivertHelperCompileFilter);

#undef LOAD_SYM

    g_wd.module = hMod;
    return true;
}

void wd_unload_library(void) {
    if (g_wd.module) {
        FreeLibrary(g_wd.module);
        ZeroMemory(&g_wd, sizeof(g_wd));
    }
}
