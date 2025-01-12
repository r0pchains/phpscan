#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>

#define BUFFER_SIZE 1024
#define TARGET_EXT ".php"
#define PHP_INI_FILE "/etc/php/7.4/apache2/php.ini" // Adjust this path as necessary

// Function to check if the vulnerable functions are disabled in php.ini
bool check_disable_functions() {
    FILE *ini_file = fopen(PHP_INI_FILE, "r");
    if (!ini_file) {
        perror("Unable to open php.ini file");
        return false;
    }

    char buffer[BUFFER_SIZE];
    bool found_disabled = false;
    const char *vulnerable_functions[] = {
        "exec",
        "system",
        "passthru",
        "shell_exec",
        "proc_open",
        "eval"
    };

    while (fgets(buffer, BUFFER_SIZE, ini_file)) {
        if (strstr(buffer, "disable_functions")) {
            // Check if any of the vulnerable functions are in the disable list
            for (size_t i = 0; i < sizeof(vulnerable_functions) / sizeof(vulnerable_functions[0]); i++) {
                if (strstr(buffer, vulnerable_functions[i])) {
                    found_disabled = true;
                    break;
                }
            }
            break; // We found the disable_functions line, no need to check further
        }
    }

    fclose(ini_file);
    return found_disabled;
}

// Function to check if a file contains any of the specified functions and safeguards
void check_vulnerable_functions(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    const char *vulnerable_functions[] = {
        "eval(",
        "exec(",
        "system(",
        "passthru(",
        "shell_exec(",
        "proc_open("
    };
    const char *function_names[] = {
        "eval()",
        "exec()",
        "system()",
        "passthru()",
        "shell_exec()",
        "proc_open()"
    };
    size_t num_functions = sizeof(vulnerable_functions) / sizeof(vulnerable_functions[0]);
    int function_count[6] = {0}; // Count occurrences of each function
    bool found_vuln = false;
    bool has_safeguard = false;

    while (fgets(buffer, BUFFER_SIZE, file)) {
        for (size_t i = 0; i < num_functions; i++) {
            if (strstr(buffer, vulnerable_functions[i])) {
                function_count[i]++;
                found_vuln = true; // Indicate that we've found at least one vuln
            }
        }
        // Check for common safeguards
        if (strstr(buffer, "if (") && strstr(buffer, "isset(")) {
            has_safeguard = true;
        }
        if (strstr(buffer, "disable_functions") || strstr(buffer, "exit(") || strstr(buffer, "die(")) {
            has_safeguard = true;
        }
    }

    if (found_vuln) {
        printf("Vulnerable PHP file found: %s\n", filename);
        for (size_t i = 0; i < num_functions; i++) {
            if (function_count[i] > 0) {
                printf("  - Found vulnerable function: %s (Count: %d)\n", function_names[i], function_count[i]);
            }
        }
        if (has_safeguard) {
            printf("  - Safeguards detected: Yes\n");
        } else {
            printf("  - Safeguards detected: No\n");
        }
    }

    fclose(file);
}

// Function to scan a directory for PHP files
void scan_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;

    if (!dir) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Construct the full path for the file
        char full_path[BUFFER_SIZE];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        // Check if it's a directory or a file
        if (entry->d_type == DT_DIR) {
            // Ignore the "." and ".." directories
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                // Recursively scan the subdirectory
                scan_directory(full_path);
            }
        } else if (entry->d_type == DT_REG) {
            // Check if it's a PHP file
            if (strstr(entry->d_name, TARGET_EXT)) {
                // Check for vulnerable functions in the PHP file
                check_vulnerable_functions(full_path);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bool disable_functions_check = check_disable_functions();
    printf("Vulnerable functions disabled in php.ini: %s\n", disable_functions_check ? "Yes" : "No");

    scan_directory(argv[1]);
    return EXIT_SUCCESS;
}
