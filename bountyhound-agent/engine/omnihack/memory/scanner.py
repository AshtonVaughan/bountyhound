"""
OMNIHACK Memory Scanner
Pattern-based memory scanning for game processes
"""
import pymem
import pymem.process
import struct
import re
from typing import List, Optional, Tuple
from pathlib import Path

class MemoryScanner:
    """Advanced memory scanning with pattern matching"""

    def __init__(self, process_name: str):
        """Initialize scanner for target process"""
        try:
            self.pm = pymem.Pymem(process_name)
            self.process_name = process_name
            self.base_address = self.pm.process_base.lpBaseOfDll
            print(f"[+] Attached to {process_name}")
            print(f"[+] Base address: 0x{self.base_address:X}")
        except Exception as e:
            raise Exception(f"Failed to attach to {process_name}: {e}")

    def pattern_to_bytes(self, pattern: str) -> Tuple[bytes, bytes]:
        """
        Convert IDA-style pattern to bytes and mask
        Example: "F3 0F 10 05 ?? ?? ?? ??" -> bytes + mask
        """
        parts = pattern.split()
        pattern_bytes = bytearray()
        mask = bytearray()

        for part in parts:
            if part == "??":
                pattern_bytes.append(0)
                mask.append(0)
            else:
                pattern_bytes.append(int(part, 16))
                mask.append(1)

        return bytes(pattern_bytes), bytes(mask)

    def scan_pattern(self, pattern: str, start_address: Optional[int] = None,
                     end_address: Optional[int] = None) -> List[int]:
        """
        Scan memory for AOB pattern
        Returns list of addresses where pattern is found
        """
        pattern_bytes, mask = self.pattern_to_bytes(pattern)
        results = []

        # Default to full process memory
        if start_address is None:
            start_address = self.base_address
        if end_address is None:
            end_address = self.base_address + 0x10000000  # 256MB

        print(f"[*] Scanning for pattern: {pattern}")
        print(f"[*] Range: 0x{start_address:X} - 0x{end_address:X}")

        # Scan in chunks
        chunk_size = 4096  # 4KB chunks
        current_address = start_address

        while current_address < end_address:
            try:
                # Read memory chunk
                data = self.pm.read_bytes(current_address, chunk_size)

                # Search for pattern in chunk
                for i in range(len(data) - len(pattern_bytes) + 1):
                    match = True
                    for j in range(len(pattern_bytes)):
                        if mask[j] and data[i + j] != pattern_bytes[j]:
                            match = False
                            break

                    if match:
                        address = current_address + i
                        results.append(address)
                        print(f"[+] Found at 0x{address:X}")

                current_address += chunk_size

            except Exception:
                # Skip inaccessible memory regions
                current_address += chunk_size
                continue

        print(f"[*] Scan complete. Found {len(results)} matches")
        return results

    def read_int(self, address: int) -> int:
        """Read 4-byte integer from address"""
        return self.pm.read_int(address)

    def read_float(self, address: int) -> float:
        """Read 4-byte float from address"""
        return self.pm.read_float(address)

    def read_double(self, address: int) -> float:
        """Read 8-byte double from address"""
        return self.pm.read_double(address)

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read raw bytes from address"""
        return self.pm.read_bytes(address, size)

    def read_string(self, address: int, max_length: int = 256) -> str:
        """Read null-terminated string from address"""
        data = self.pm.read_bytes(address, max_length)
        end = data.find(b'\x00')
        if end != -1:
            return data[:end].decode('utf-8', errors='ignore')
        return data.decode('utf-8', errors='ignore')

    def resolve_pointer_chain(self, base_address: int, offsets: List[int]) -> int:
        """
        Resolve multi-level pointer chain
        Example: [[base+0x100]+0x20]+0x10 -> final address
        """
        current = base_address

        for i, offset in enumerate(offsets[:-1]):
            current = self.pm.read_int(current + offset)
            if current == 0:
                raise Exception(f"Null pointer at level {i}")

        return current + offsets[-1]

    def dump_region(self, address: int, size: int, filename: str):
        """Dump memory region to file with path traversal protection"""
        # Security: Validate filename
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be empty")

        # Security: Strip directory components to prevent path traversal
        safe_filename = Path(filename).name

        # Security: Ensure dumps directory exists and restrict writes to it
        dumps_dir = Path("dumps")
        dumps_dir.mkdir(exist_ok=True)

        # Construct safe output path
        output_path = dumps_dir / safe_filename

        # Read memory from process
        data = self.pm.read_bytes(address, size)

        # Write to safe location
        with open(output_path, 'wb') as f:
            f.write(data)

        print(f"[+] Dumped {len(data)} bytes to {output_path}")

    def __del__(self):
        """Cleanup"""
        if hasattr(self, 'pm'):
            self.pm.close_process()


if __name__ == "__main__":
    # Example usage
    scanner = MemoryScanner("FortniteClient-Win64-Shipping.exe")

    # Scan for player coordinate pattern
    coords = scanner.scan_pattern("F3 0F 10 05 ?? ?? ?? ?? F3 0F 11 45")

    if coords:
        print(f"\n[+] Player coordinates found at: 0x{coords[0]:X}")
        x = scanner.read_float(coords[0])
        y = scanner.read_float(coords[0] + 4)
        z = scanner.read_float(coords[0] + 8)
        print(f"[+] Position: X={x}, Y={y}, Z={z}")
