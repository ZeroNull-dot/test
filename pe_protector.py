"""
PE Protector - Academic Research Tool
Injects position-independent stub with XOR-encrypted payload
"""

import struct
import lief
import random
from pathlib import Path

META_OFFSET = 0x200


class ProtectionWorker:
    """Core PE protection logic (extracted from PyQt6 GUI version)"""
    
    def __init__(self, input_exe: str, output_exe: str, config: dict = None):
        self.input = input_exe
        self.output = output_exe
        self.config = config or {}
        self.logs = []

    def log(self, msg: str):
        self.logs.append(msg)
        print(msg)

    def protect(self) -> bool:
        """Main protection routine. Returns True on success."""
        try:
            # Parse target PE
            self.log(f"[*] Parsing {self.input}")
            binary = lief.parse(self.input)
            if not binary:
                self.log("❌ Failed to parse PE")
                return False

            # Detect architecture
            is_x64 = binary.optional_header.magic == 0x20b
            arch_str = "x64" if is_x64 else "x86"
            self.log(f"[*] Target architecture: {arch_str}")

            # Load appropriate stub
            stub_name = "stub_x64.exe" if is_x64 else "stub_x86.exe"
            stub_path = Path(self.input).parent / stub_name
            if not stub_path.exists():
                # Try current directory
                stub_path = Path(stub_name)
            if not stub_path.exists():
                self.log(f"❌ {stub_name} not found")
                return False
            
            self.log(f"[*] Loading stub: {stub_path}")
            stub_pe = lief.parse(str(stub_path))
            stub_sec = stub_pe.get_section(".text")
            if not stub_sec:
                self.log("❌ Stub .text section not found")
                return False
            
            stub_code = bytes(stub_sec.content)
            self.log(f"[*] Stub code size: {len(stub_code)} bytes")

            # Generate configuration
            xor_key = self.config.get("xor_key", random.randint(0x10000000, 0xFFFFFFFF))
            original_oep = binary.optional_header.addressof_entrypoint
            payload_size = self.config.get("payload_size", 0x1000)
            
            self.log(f"[*] Original OEP: 0x{original_oep:X}")
            self.log(f"[*] XOR Key: 0x{xor_key:X}")
            self.log(f"[*] Payload size: 0x{payload_size:X}")

            # Create dummy encrypted payload
            payload = bytearray(payload_size)
            for i in range(payload_size):
                payload[i] = (i ^ ((xor_key >> ((i % 4) * 8)) & 0xFF)) & 0xFF

            # Calculate metadata size (4 pointers)
            meta_size = 32 if is_x64 else 16
            
            # Build .prot section content: [stub code] + [padding] + [metadata] + [payload]
            raw_layout = stub_code.ljust(META_OFFSET, b'\x00') + b'\x00' * meta_size + bytes(payload)
            
            # Create new section
            prot_section = lief.PE.Section(".prot")
            prot_section.content = bytearray(raw_layout)
            # CODE | EXECUTE | READ | WRITE (allows decryption then restore)
            prot_section.characteristics = 0xE0000020  

            # Calculate aligned RVA for new section
            sec_align = binary.optional_header.section_alignment or 0x1000
            max_end = max((s.virtual_address + s.virtual_size for s in binary.sections), default=0)
            prot_rva = (max_end + sec_align - 1) & ~(sec_align - 1)
            
            prot_section.virtual_address = prot_rva
            prot_section.virtual_size = len(raw_layout)
            
            self.log(f"[*] .prot section RVA: 0x{prot_rva:X}")
            self.log(f"[*] .prot section size: {len(raw_layout)} bytes")

            # Add section to PE
            binary.add_section(prot_section)
            
            # Verify section was added correctly
            added_sec = binary.get_section(".prot")
            if not added_sec:
                self.log("❌ Failed to add .prot section")
                return False
            
            # Calculate payload RVA (after metadata)
            payload_rva = prot_rva + META_OFFSET + meta_size
            
            # Pack metadata structure
            fmt = "<QQQQ" if is_x64 else "<IIII"
            meta_bytes = struct.pack(fmt, original_oep, payload_rva, payload_size, xor_key)
            
            # Inject metadata into section content
            content = bytearray(prot_section.content)
            content[META_OFFSET:META_OFFSET+meta_size] = meta_bytes
            prot_section.content = content
            
            self.log(f"[*] Metadata injected at offset 0x{META_OFFSET:X}")
            self.log(f"[*] Payload RVA: 0x{payload_rva:X}")

            # Redirect entry point to stub
            binary.optional_header.addressof_entrypoint = prot_rva
            self.log(f"[*] New Entry Point: 0x{prot_rva:X}")

            # Disable ASLR (required since we don't handle relocations)
            binary.optional_header.dll_characteristics &= ~0x0040
            self.log("[*] ASLR disabled")

            # Strip relocation directory (LIEF breaks it when adding sections)
            # This prevents Windows loader from trying to apply broken relocations
            if len(binary.data_directories) > 5:
                reloc_dir = binary.data_directories[5]
                reloc_dir.rva = 0
                reloc_dir.size = 0
                self.log("[*] Relocation directory stripped")

            # Critical: Expand SizeOfImage so Windows maps the new section
            # This is required per PE spec - SizeOfImage must cover all sections
            new_image_size = prot_rva + len(raw_layout)
            binary.optional_header.sizeof_image = (new_image_size + sec_align - 1) & ~(sec_align - 1)
            self.log(f"[*] SizeOfImage expanded to 0x{binary.optional_header.sizeof_image:X}")

            # Write output
            self.log(f"[*] Writing protected executable: {self.output}")
            binary.write(self.output)
            
            self.log(f"✅ Protection complete: {self.output}")
            return True
            
        except Exception as e:
            import traceback
            self.log(f"❌ Error: {e}")
            self.log(traceback.format_exc())
            return False


def main():
    """CLI interface for testing"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python pe_protector.py <input.exe> <output.exe> [xor_key]")
        print("Example: python pe_protector.py test_app.exe test_app_protected.exe 0x5A5A5A5A")
        sys.exit(1)
    
    input_exe = sys.argv[1]
    output_exe = sys.argv[2]
    xor_key = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    
    config = {}
    if xor_key:
        config["xor_key"] = xor_key
    
    worker = ProtectionWorker(input_exe, output_exe, config)
    success = worker.protect()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
