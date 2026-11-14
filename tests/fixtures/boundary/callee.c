#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Dangling sink in native implementation
void execute_native_operation(const char *command) {
    char buffer[256];
    // Sensitive sink: vulnerable buffer copy
    strcpy(buffer, command);
    system(buffer);
}
