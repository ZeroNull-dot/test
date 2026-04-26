# PE Protector - Academic Research Tool

A position-independent PE packer/protector for academic research purposes. Injects a zero-CRT, IAT-free stub that encrypts payloads with XOR, implements Anti-VM checks, and redirects execution flow.

## 🎯 Features

- **Position-independent stub**: No relocations, works at any image base
- **Zero CRT dependency**: Uses only native Windows APIs resolved dynamically
- **IAT-free**: All API resolution via PEB/LDR walking
- **XOR encryption**: Simple payload encryption with configurable key
- **Anti-VM checks**: 
  - CPUID hypervisor bit detection (bit 31)
  - RDTSC timing analysis (multiple samples)
- **Cross-architecture**: Supports both x86 and x64 targets
- **Memory protection**: Decrypts payload in-place, restores PAGE_EXECUTE_READ

## 📁 Files

| File | Description |
|------|-------------|
| `stub_code.cpp` | C++ stub source (zero-CRT, position-independent) |
| `pe_protector.py` | Python injector using LIEF |
| `test_app.cpp` | Sample test application |
| `build.bat` | Windows build script |
| `README.md` | This documentation |

## 🛠️ Build Instructions

### Prerequisites
- Windows 10/11 with Visual Studio (MSVC)
- Python 3.8+ with `lief` package (`pip install lief`)
- x64 Native Tools Command Prompt for VS

### Step 1: Compile Stubs

```cmd
:: For x64 targets
cl.exe /O1 /GS- /sdl- /DYNAMICBASE:NO /FIXED /GR- /EHs-c- stub_code.cpp ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:StubEntry /MACHINE:X64 /OUT:stub_x64.exe

:: For x86 targets  
cl.exe /O1 /GS- /sdl- /DYNAMICBASE:NO /FIXED /GR- /EHs-c- stub_code.cpp ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:StubEntry /MACHINE:X86 /OUT:stub_x86.exe
```

**Compiler flags explained:**
- `/O1` - Optimize for size
- `/GS-` - Disable buffer security checks (CRT dependency)
- `/sdl-` - Disable SDL security features
- `/DYNAMICBASE:NO` - Disable ASLR (stub must be at fixed RVA)
- `/FIXED` - Produce fixed-address executable
- `/GR-` - Disable RTTI
- `/EHs-c-` - Disable C++ exceptions

### Step 2: Compile Test Application

```cmd
cl.exe /O2 test_app.cpp /link /OUT:test_app.exe
```

### Step 3: Protect Target Executable

```cmd
python pe_protector.py test_app.exe test_app_protected.exe 0x5A5A5A5A
```

Or run without arguments for interactive mode.

### Step 4: Execute Protected Binary

```cmd
test_app_protected.exe
echo %ERRORLEVEL%
```

**Expected results:**
- **On physical hardware**: Exit code `0`, creates `test_app_protected.txt`
- **In VM/hypervisor**: Exit code `57005` (0xDEAD), no file created

## 🔬 Technical Details

### Stub Architecture

```
.prot section layout:
├─────────────────────┐
│   Stub Code         │  0x000 - 0x1FF
├─────────────────────┤
│   Metadata          │  0x200 - 0x21F (x64) / 0x20F (x86)
├─────────────────────┤
│   Encrypted Payload │  0x220+ (x64) / 0x210+ (x86)
└─────────────────────┘
```

### Metadata Structure

```cpp
struct ProtectorMeta {
    uintptr_t OriginalOEP;    // Original entry point RVA
    uintptr_t PayloadRVA;     // Encrypted payload RVA
    uintptr_t PayloadSize;    // Payload size in bytes
    uintptr_t XorKey;         // 32-bit XOR key
};
```

### Protection Flow

1. **Injection Phase** (Python):
   - Parse target PE with LIEF
   - Extract stub `.text` section
   - Generate encrypted dummy payload
   - Create `.prot` section with stub + metadata + payload
   - Redirect OEP to stub
   - Disable ASLR, strip relocations
   - Expand `SizeOfImage`

2. **Runtime Phase** (Stub):
   - Resolve `kernel32.dll` via PEB/LDR
   - Dynamically resolve `ExitProcess`, `VirtualProtect`
   - Run Anti-VM checks (CPUID + RDTSC)
   - Locate `.prot` section by name
   - Read metadata structure
   - Decrypt payload with XOR
   - Restore page protections
   - Jump to original OEP

### Anti-VM Techniques

1. **CPUID Hypervisor Bit**: Checks leaf 1, ECX bit 31
   - Returns TRUE if hypervisor is present
   - Detects VMware, VirtualBox, Hyper-V, QEMU

2. **RDTSC Timing Analysis**: 
   - Executes tight loop, measures cycle count
   - Multiple samples averaged for accuracy
   - VMs typically execute faster due to host resources
   - Threshold: < 0x50000 cycles = likely VM

## ⚠️ Limitations & Warnings

### Academic Use Only
This tool is for **educational and research purposes only**. Do not use for:
- Malware development
- Software piracy
- Evading security products
- Any illegal activities

### Known Limitations

1. **No relocation support**: ASLR must be disabled on target
2. **TLS callbacks not preserved**: Target TLS won't execute before stub
3. **CFG incompatible**: Control Flow Guard will block stub jumps
4. **Section count limit**: PE format limits to 96 sections
5. **Simple encryption**: XOR is trivially breakable
6. **Static Anti-VM**: Easily bypassed with patched hypervisors

### Compatibility Issues

| Feature | Status | Notes |
|---------|--------|-------|
| UPX-packed targets | ❌ | Unpack first |
| .NET assemblies | ❌ | Different format |
| DLLs | ⚠️ | Untested, DllMain complications |
| ARM64 | ❌ | x86/x64 only |
| Windows 7 | ⚠️ | May need PEB offset adjustments |
| VBS/HVCI enabled | ❌ | Kernel-level protections block injection |

## 🔍 Troubleshooting

### Exit Code 0xBAD0 (3072)
- **Cause**: Failed to get image base from PEB
- **Fix**: Verify PEB offsets for target OS version

### Exit Code 0xBAD1 (3073)
- **Cause**: `.prot` section not found
- **Fix**: Check section name is exactly ".prot" (5 chars)

### Exit Code 0xBAD2 (3074)
- **Cause**: Invalid metadata (OEP = 0 or -1)
- **Fix**: Verify metadata injection in Python script

### Exit Code 0xDEAD (57005)
- **Cause**: Anti-VM check triggered
- **Fix**: Run on physical hardware or disable VM detection

### Access Violation (0xC0000005)
- **Causes**:
  - ASLR still enabled (check `dll_characteristics`)
  - Relocation directory not stripped
  - `SizeOfImage` not expanded
  - Section lacks WRITE permission during decryption
- **Fix**: Verify all PE header modifications applied

## 📚 References

- [PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PEB/LDR Structures](https://www.nirsoft.net/kernel_struct/vista/PEB.html)
- [LIEF Documentation](https://lief.quarkslab.com/)
- [MSVC Compiler Options](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-by-category)

## 🧪 Research Extensions

Potential improvements for academic study:

1. **Advanced Encryption**: Replace XOR with ChaCha20 or AES-NI
2. **Anti-analysis**: Add debugger detection (IsDebuggerPresent, NtQueryInformationProcess)
3. **Code virtualization**: Implement basic VM-based protection
4. **Polymorphism**: Randomize stub instruction ordering
5. **Section hiding**: Use overlapping sections or invalid headers
6. **Import obfuscation**: Delay-load + hash-based import resolution
7. **Exception handling**: SEH-based anti-debugging
8. **Environment checks**: Memory size, disk size, uptime analysis

## 📄 License

MIT License - Academic/Research Use Only

This software is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this program.
