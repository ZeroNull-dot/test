// stub_code.cpp - Academic Research Protector Stub (Zero CRT, x86/x64)
// Compiles with: cl.exe /O1 /GS- /sdl- /DYNAMICBASE:NO /FIXED /GR- /EHs-c- stub_code.cpp /link /SUBSYSTEM:CONSOLE /ENTRY:StubEntry /MACHINE:X64 /OUT:stub_x64.exe

#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/MERGE:.data=.text")
#pragma optimize("", off)

#include <windows.h>
#include <intrin.h>
#include <stdint.h>

#pragma warning(disable: 4201 4100 4706 6387 6011)

#define META_OFFSET 0x200

struct ProtectorMeta {
    uintptr_t OriginalOEP;
    uintptr_t PayloadRVA;
    uintptr_t PayloadSize;
    uintptr_t XorKey;
};

typedef struct _MY_UNICODE_STRING { 
    USHORT Length; 
    USHORT MaximumLength; 
    PWSTR Buffer; 
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

// Get module handle from PEB/LDR
static HMODULE GetMod(const char* name) {
#ifdef _M_X64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
    PBYTE ldr = *(PBYTE*)(peb + 0x18);
    PLIST_ENTRY head = (PLIST_ENTRY)(ldr + 0x10);
    const size_t BASE_OFF = 0x30, NAME_OFF = 0x58;
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
    PBYTE ldr = *(PBYTE*)(peb + 0x0C);
    PLIST_ENTRY head = (PLIST_ENTRY)(ldr + 0x0C);
    const size_t BASE_OFF = 0x18, NAME_OFF = 0x2C;
#endif
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        PBYTE entry = (PBYTE)curr;
        if (!name) return (HMODULE)*(PVOID*)(entry + BASE_OFF);
        PMY_UNICODE_STRING baseName = (PMY_UNICODE_STRING)(entry + NAME_OFF);
        if (baseName && baseName->Buffer && baseName->Length > 0) {
            int match = 1;
            for (USHORT i = 0; i < baseName->Length / 2; i++) {
                char c = (char)baseName->Buffer[i], n = name[i];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (n >= 'A' && n <= 'Z') n += 32;
                if (c != n) { match = 0; break; }
                if (n == 0) break;
            }
            if (match && name[0] != 0) return (HMODULE)*(PVOID*)(entry + BASE_OFF);
        }
        curr = curr->Flink;
    }
    return NULL;
}

// Get procedure address by walking export table
static FARPROC GetProc(HMODULE hMod, const char* name) {
    if (!hMod || !name) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    DWORD expRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRVA) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)hMod + expRVA);
    if (!exp->NumberOfNames) return NULL;
    DWORD* names = (DWORD*)((uintptr_t)hMod + exp->AddressOfNames);
    WORD* ords = (WORD*)((uintptr_t)hMod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((uintptr_t)hMod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* ename = (const char*)((uintptr_t)hMod + names[i]);
        int match = 1;
        for (int j = 0; ; j++) { 
            if (name[j] != ename[j]) { match = 0; break; } 
            if (name[j] == 0) break; 
        }
        if (match) return (FARPROC)((uintptr_t)hMod + funcs[ords[i]]);
    }
    return NULL;
}

// Anti-VM: CPUID hypervisor bit + RDTSC timing
static BOOL IsVM() {
    int cpu[4] = {0};
    __cpuid(cpu, 1);
    if (cpu[2] & (1 << 31)) return TRUE;  // Hypervisor present bit
    
    // RDTSC timing check with multiple samples
    unsigned __int64 t1, t2, total = 0;
    for (int sample = 0; sample < 3; sample++) {
        _mm_lfence(); 
        t1 = __rdtsc(); 
        _mm_lfence();
        for (volatile int i = 0; i < 0x100000; i++);
        _mm_lfence(); 
        t2 = __rdtsc(); 
        _mm_lfence();
        total += (t2 - t1);
    }
    return (total / 3) < 0x50000;  // Too fast = likely VM
}

// Verify PE header integrity
static BOOL VerifyPEHeader(HMODULE hMod) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

extern "C" void __cdecl StubEntry() {
    // Stack-allocated strings to avoid .rdata
    char s_k32[13] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    char s_exit[12] = {'E','x','i','t','P','r','o','c','e','s','s',0};
    char s_vp[15] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};

    HMODULE hKernel = GetMod(s_k32);
    auto fnExit = hKernel ? (void(WINAPI*)(UINT))GetProc(hKernel, s_exit) : NULL;
    auto fnVP   = hKernel ? (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))GetProc(hKernel, s_vp) : NULL;

    // Anti-VM check
    if (IsVM()) { 
        if(fnExit) fnExit(0xDEAD); 
        return; 
    }

    // Get our own image base from PEB
#ifdef _M_X64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
    HMODULE hMod = *(HMODULE*)(peb + 0x10);
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
    HMODULE hMod = *(HMODULE*)(peb + 0x08);
#endif
    if (!hMod) { 
        if(fnExit) fnExit(0xBAD0); 
        return; 
    }

    // Verify PE integrity
    if (!VerifyPEHeader(hMod)) {
        if(fnExit) fnExit(0xBAD0);
        return;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)hMod + ((PIMAGE_DOS_HEADER)hMod)->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    uintptr_t protRVA = 0;
    
    // Find .prot section
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 'p' && 
            sec[i].Name[2] == 'r' && sec[i].Name[3] == 'o' && 
            sec[i].Name[4] == 't') {
            protRVA = sec[i].VirtualAddress; 
            break;
        }
    }
    if (!protRVA) { 
        if(fnExit) fnExit(0xBAD1); 
        return; 
    }

    // Read metadata
    ProtectorMeta* meta = (ProtectorMeta*)((uintptr_t)hMod + protRVA + META_OFFSET);
    if (!meta->OriginalOEP || meta->OriginalOEP == (uintptr_t)-1) {
        if(fnExit) fnExit(0xBAD2); 
        return;
    }

    // Decrypt payload
    BYTE* payload = (BYTE*)((uintptr_t)hMod + meta->PayloadRVA);
    DWORD old;
    for (uintptr_t off = 0; off < meta->PayloadSize; off += 0x1000) {
        uintptr_t sz = (meta->PayloadSize - off < 0x1000) ? (meta->PayloadSize - off) : 0x1000;
        BYTE* p = payload + off;
        DWORD tmp;
        
        // Temporarily set to READWRITE for decryption
        if (fnVP) fnVP(p, sz, PAGE_READWRITE, &tmp);
        
        // XOR decrypt
        for (uintptr_t i = 0; i < sz; i++) 
            p[i] ^= (BYTE)((meta->XorKey >> ((i % 4) * 8)) & 0xFF);
        
        // Restore to EXECUTE_READ
        if (fnVP) fnVP(p, sz, PAGE_EXECUTE_READ, &old);
    }

    // Jump to original entry point
    typedef int(__cdecl* OEP_t)();
    OEP_t Target = (OEP_t)((uintptr_t)hMod + meta->OriginalOEP);
    int ret = Target();
    
    if (fnExit) fnExit((UINT)ret);
}
