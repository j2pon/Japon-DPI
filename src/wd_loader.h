#ifndef JAPONDPI_WD_LOADER_H
#define JAPONDPI_WD_LOADER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/* Include WinDivert structs & constants without static dllimport bindings */
#define WINDIVERT_KERNEL
#include "windivert.h"
#undef WINDIVERT_KERNEL

typedef HANDLE (*pfn_WinDivertOpen)(
    const char *filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
typedef BOOL (*pfn_WinDivertRecv)(
    HANDLE handle, VOID *pPacket, UINT packetLen, UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr);
typedef BOOL (*pfn_WinDivertSend)(
    HANDLE handle, const VOID *pPacket, UINT packetLen, UINT *pSendLen, const WINDIVERT_ADDRESS *pAddr);
typedef BOOL (*pfn_WinDivertShutdown)(
    HANDLE handle, WINDIVERT_SHUTDOWN how);
typedef BOOL (*pfn_WinDivertClose)(
    HANDLE handle);
typedef BOOL (*pfn_WinDivertSetParam)(
    HANDLE handle, WINDIVERT_PARAM param, UINT64 value);
typedef BOOL (*pfn_WinDivertGetParam)(
    HANDLE handle, WINDIVERT_PARAM param, UINT64 *pValue);
typedef BOOL (*pfn_WinDivertHelperParsePacket)(
    const VOID *pPacket, UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr, PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    UINT8 *pProtocol,
    PWINDIVERT_ICMPHDR *ppIcmpHdr, PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr, PWINDIVERT_UDPHDR *ppUdpHdr,
    PVOID *ppData, UINT *pDataLen,
    PVOID *ppNext, UINT *pNextLen);
typedef BOOL (*pfn_WinDivertHelperCalcChecksums)(
    VOID *pPacket, UINT packetLen, WINDIVERT_ADDRESS *pAddr, UINT64 flags);
typedef BOOL (*pfn_WinDivertHelperCompileFilter)(
    const char *filter, WINDIVERT_LAYER layer, char *object, UINT objLen,
    const char **errorStr, UINT *errorPos);

typedef struct {
    HMODULE                          module;
    pfn_WinDivertOpen                Open;
    pfn_WinDivertRecv                Recv;
    pfn_WinDivertSend                Send;
    pfn_WinDivertShutdown            Shutdown;
    pfn_WinDivertClose               Close;
    pfn_WinDivertSetParam            SetParam;
    pfn_WinDivertGetParam            GetParam;
    pfn_WinDivertHelperParsePacket   HelperParsePacket;
    pfn_WinDivertHelperCalcChecksums HelperCalcChecksums;
    pfn_WinDivertHelperCompileFilter HelperCompileFilter;
} WinDivertAPI;

extern WinDivertAPI g_wd;

/* Loads WinDivert.dll from the same directory as japondpi.exe */
bool wd_load_library(char *err_buf, size_t err_buf_len);
void wd_unload_library(void);

/* Returns directory containing current executable (no trailing slash) */
bool get_exe_dir_w(wchar_t *buf, DWORD buf_chars);

#endif /* JAPONDPI_WD_LOADER_H */
