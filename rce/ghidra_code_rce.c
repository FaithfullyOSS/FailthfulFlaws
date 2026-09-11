#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>

#define PATTERNS_COUNT 6
const char *PATTERNS[] = {
    "def execute(",
    "gdb.execute(cmd",
    "exec_convert_errors(cmd",
    "def pyeval(",
    "return eval(expr)",
    "EvaluateExpression(expr)"
};

#define PAYLOAD_COMMAND "id && whoami && uname -a"

char *default_source() {
    char *env = getenv("GHIDRA_SOURCE");
    if (env && access(env, F_OK) == 0) {
        return strdup(env);
    }

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd))) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/ghidra-12.1.2", cwd);
        if (access(path, F_OK) == 0) {
            return strdup(path);
        }
    }

    char script_dir[PATH_MAX];
    if (readlink("/proc/self/exe", script_dir, sizeof(script_dir)) > 0) {
        char *last = strrchr(script_dir, '/');
        if (last) *last = '\0';
        last = strrchr(script_dir, '/');
        if (last) *last = '\0';
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/ghidra-12.1.2", script_dir);
        if (access(path, F_OK) == 0) {
            return strdup(path);
        }
    }

    return NULL;
}

int is_methods_py(const char *name) {
    return strstr(name, "methods.py") != NULL;
}

void find_and_report_hits(const char *root) {
    DIR *dir = opendir(root);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", root, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                find_and_report_hits(path);
            } else if (S_ISREG(st.st_mode) && is_methods_py(entry->d_name)) {
                FILE *f = fopen(path, "r");
                if (f) {
                    char line[4096];
                    int line_no = 0;
                    while (fgets(line, sizeof(line), f)) {
                        line_no++;
                        char *stripped = line;
                        while (*stripped == ' ' || *stripped == '\t') stripped++;
                        for (int i = 0; i < PATTERNS_COUNT; i++) {
                            if (strstr(stripped, PATTERNS[i])) {
                                printf("[hit] %s:%d\n", path, line_no);
                                break;
                            }
                        }
                    }
                    fclose(f);
                }
            }
        }
    }
    closedir(dir);
}

int main() {
    char *source = default_source();
    if (!source) {
        fprintf(stderr, "Failed to locate Ghidra source.\n");
        return 1;
    }

    char out_dir[PATH_MAX];
    snprintf(out_dir, sizeof(out_dir), "%s/artifacts/tracermi-conditional-rce", dirname(strdup(source)));
    mkdir(out_dir, 0755);

    char shapes_path[PATH_MAX];
    snprintf(shapes_path, sizeof(shapes_path), "%s/tracermi_calc_payload_shapes.txt", out_dir);

    FILE *sf = fopen(shapes_path, "w");
    if (sf) {
        fprintf(sf, "GDB: %s\n", PAYLOAD_COMMAND);
        fprintf(sf, "LLDB cmd: %s\n", PAYLOAD_COMMAND);
        fprintf(sf, "LLDB expr: %s\n", PAYLOAD_COMMAND);
        fclose(sf);
    }

    find_and_report_hits(source);

    printf("Running: %s\n", PAYLOAD_COMMAND);
    int ret = system(PAYLOAD_COMMAND);
    free(source);
    return ret == -1 ? 1 : 0;
}