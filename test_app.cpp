// test_app.cpp - Simple test application for PE Protector
// Compiles with: cl.exe /O2 test_app.cpp /link /OUT:test_app.exe

#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    
    // Create success marker file
    char* ext = strrchr(path, '.');
    if (ext) strcpy(ext, ".txt");
    
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "✅ Stub passed checks, decrypted payload, and reached OEP!\n");
        fprintf(f, "Process completed successfully.\n");
        fclose(f);
        printf("Success: %s created.\n", path);
        return 0;
    } else {
        printf("Failed to create file.\n");
        return 1;
    }
}
