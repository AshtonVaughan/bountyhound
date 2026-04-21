"""
Binary Patcher
Binary patching toolkit for security research. Supports byte-level
patching, NOP sleds, string replacement, jump modification, and
automated bypass of license checks, anti-debug, and integrity verification.
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from colorama import Fore, Style


@dataclass
class Patch:
    """Represents a single patch applied to the binary"""
    offset: int
    original: bytes
    patched: bytes
    description: str
    timestamp: float = field(default_factory=time.time)


class BinaryPatcher:
    """
    Binary patching engine for security research.

    Loads a binary into memory, applies patches (byte replacement,
    NOP regions, string replacement, jump modifications), and writes
    the patched result. Maintains a full patch history for undo
    and diff operations.
    """

    # Architecture-specific NOP opcodes
    NOP_OPCODES = {
        'x86': b'\x90',        # NOP
        'x86_64': b'\x90',     # NOP
        'ARM': b'\x00\x00\xa0\xe1',      # MOV R0, R0 (ARM mode NOP)
        'ARM_THUMB': b'\x00\xbf',         # NOP (Thumb mode)
        'AArch64': b'\x1f\x20\x03\xd5',  # NOP
        'MIPS': b'\x00\x00\x00\x00',     # SLL $zero, $zero, 0
    }

    # x86 conditional jump opcodes and their unconditional replacement
    X86_JUMPS = {
        0x74: 'JZ',    # Jump if Zero
        0x75: 'JNZ',   # Jump if Not Zero
        0x76: 'JBE',   # Jump if Below or Equal
        0x77: 'JA',    # Jump if Above
        0x78: 'JS',    # Jump if Sign
        0x79: 'JNS',   # Jump if Not Sign
        0x7C: 'JL',    # Jump if Less
        0x7D: 'JGE',   # Jump if Greater or Equal
        0x7E: 'JLE',   # Jump if Less or Equal
        0x7F: 'JG',    # Jump if Greater
    }

    # License/activation related strings to search for
    LICENSE_STRINGS = [
        b'license', b'License', b'LICENSE',
        b'serial', b'Serial', b'SERIAL',
        b'activation', b'Activation',
        b'trial', b'Trial', b'TRIAL',
        b'expired', b'Expired', b'EXPIRED',
        b'registered', b'Registered',
        b'unregistered', b'Unregistered',
        b'evaluation', b'Evaluation',
        b'demo', b'Demo',
        b'valid key', b'invalid key',
        b'check_license', b'CheckLicense',
        b'verify_license', b'VerifyLicense',
        b'IsLicensed', b'is_licensed',
        b'IsRegistered', b'is_registered',
        b'IsTrial', b'is_trial',
    ]

    # Anti-debug function names to patch
    ANTI_DEBUG_TARGETS = [
        b'IsDebuggerPresent',
        b'CheckRemoteDebuggerPresent',
        b'NtQueryInformationProcess',
        b'OutputDebugStringA',
        b'OutputDebugStringW',
    ]

    # Integrity check indicators
    INTEGRITY_INDICATORS = [
        b'CRC32',
        b'crc32',
        b'checksum',
        b'Checksum',
        b'CHECKSUM',
        b'integrity',
        b'Integrity',
        b'hash_check',
        b'HashCheck',
        b'self_check',
        b'SelfCheck',
        b'tamper',
        b'Tamper',
    ]

    def __init__(self, binary_path: str):
        """
        Initialize the patcher by loading the binary into memory.

        Args:
            binary_path: Path to the binary file to patch

        Raises:
            FileNotFoundError: If the binary does not exist
            ValueError: If the path is empty or not a file
        """
        if not binary_path:
            raise ValueError("binary_path must not be empty")

        self.binary_path = Path(binary_path).resolve()

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not self.binary_path.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")

        with open(self.binary_path, 'rb') as f:
            self.data = bytearray(f.read())

        self.original = bytes(self.data)
        self.patches: List[Patch] = []
        self.arch = self._detect_arch()

        print(f"{Fore.GREEN}[+] Binary patcher initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] File: {self.binary_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Size: {len(self.data):,} bytes{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Detected arch: {self.arch}{Style.RESET_ALL}")

    def _detect_arch(self) -> str:
        """
        Auto-detect the binary architecture from magic bytes.

        Returns:
            Architecture string suitable for NOP_OPCODES lookup
        """
        if len(self.data) < 20:
            return 'x86'

        # ELF
        if self.data[:4] == b'\x7fELF':
            ei_class = self.data[4]
            e_machine_bytes = self.data[18:20]
            # Determine endianness for parsing
            if self.data[5] == 1:  # Little-endian
                e_machine = int.from_bytes(e_machine_bytes, 'little')
            else:
                e_machine = int.from_bytes(e_machine_bytes, 'big')

            if e_machine == 0x03:
                return 'x86'
            elif e_machine == 0x3E:
                return 'x86_64'
            elif e_machine == 0x28:
                return 'ARM'
            elif e_machine == 0xB7:
                return 'AArch64'
            elif e_machine == 0x08:
                return 'MIPS'

        # PE (default to x86/x86_64)
        if self.data[:2] == b'MZ' and len(self.data) >= 0x40:
            try:
                e_lfanew = int.from_bytes(self.data[0x3C:0x40], 'little')
                if e_lfanew + 6 <= len(self.data):
                    machine = int.from_bytes(self.data[e_lfanew + 4:e_lfanew + 6], 'little')
                    if machine == 0x8664:
                        return 'x86_64'
                    elif machine == 0xAA64:
                        return 'AArch64'
                    elif machine in (0x01C0, 0x01C2, 0x01C4):
                        return 'ARM'
            except (IndexError, ValueError):
                pass
            return 'x86'

        # Mach-O
        if self.data[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf'):
            return 'x86_64' if self.data[:4] == b'\xfe\xed\xfa\xcf' else 'x86'

        return 'x86'

    def patch_bytes(self, offset: int, new_bytes: bytes, description: str = '') -> bool:
        """
        Replace bytes at a specific offset in the binary.

        Args:
            offset: Byte offset to start patching
            new_bytes: Replacement bytes
            description: Human-readable description of the patch

        Returns:
            True if patch was applied successfully

        Raises:
            ValueError: If offset is out of range
        """
        if offset < 0 or offset + len(new_bytes) > len(self.data):
            raise ValueError(
                f"Patch range [{offset}:{offset + len(new_bytes)}] exceeds binary size {len(self.data)}"
            )

        original = bytes(self.data[offset:offset + len(new_bytes)])
        self.data[offset:offset + len(new_bytes)] = new_bytes

        patch = Patch(
            offset=offset,
            original=original,
            patched=bytes(new_bytes),
            description=description or f'Patch {len(new_bytes)} bytes at 0x{offset:X}',
        )
        self.patches.append(patch)

        print(f"{Fore.GREEN}[+] Patched {len(new_bytes)} bytes at 0x{offset:X}{Style.RESET_ALL}")
        return True

    def nop_region(self, offset: int, length: int, description: str = '') -> bool:
        """
        Fill a region with NOP instructions appropriate for the detected architecture.

        Args:
            offset: Start offset of the region to NOP out
            length: Number of bytes to fill with NOPs
            description: Human-readable description

        Returns:
            True if the NOP sled was applied successfully

        Raises:
            ValueError: If the region exceeds binary bounds
        """
        if offset < 0 or offset + length > len(self.data):
            raise ValueError(
                f"NOP range [{offset}:{offset + length}] exceeds binary size {len(self.data)}"
            )

        nop = self.NOP_OPCODES.get(self.arch, b'\x90')
        nop_len = len(nop)

        # Build NOP sled that covers the requested length
        nop_sled = (nop * ((length // nop_len) + 1))[:length]

        original = bytes(self.data[offset:offset + length])
        self.data[offset:offset + length] = nop_sled

        patch = Patch(
            offset=offset,
            original=original,
            patched=bytes(nop_sled),
            description=description or f'NOP {length} bytes at 0x{offset:X} ({self.arch})',
        )
        self.patches.append(patch)

        print(f"{Fore.GREEN}[+] NOP'd {length} bytes at 0x{offset:X}{Style.RESET_ALL}")
        return True

    def patch_string(self, old_string: str, new_string: str, description: str = '') -> int:
        """
        Find and replace a string in the binary.

        The new string must be shorter than or equal to the old string.
        Excess bytes are padded with null bytes to preserve binary layout.

        Args:
            old_string: String to find
            new_string: Replacement string (must be <= len(old_string))
            description: Human-readable description

        Returns:
            Number of replacements made

        Raises:
            ValueError: If new_string is longer than old_string
        """
        if len(new_string) > len(old_string):
            raise ValueError(
                f"New string ({len(new_string)} bytes) must be <= old string ({len(old_string)} bytes)"
            )

        old_bytes = old_string.encode('utf-8')
        # Pad with null bytes to match original length
        new_bytes = new_string.encode('utf-8') + b'\x00' * (len(old_bytes) - len(new_string.encode('utf-8')))

        count = 0
        offset = 0

        while True:
            idx = self.data.find(old_bytes, offset)
            if idx == -1:
                break

            original = bytes(self.data[idx:idx + len(old_bytes)])
            self.data[idx:idx + len(old_bytes)] = new_bytes

            patch = Patch(
                offset=idx,
                original=original,
                patched=bytes(new_bytes),
                description=description or f'String replace at 0x{idx:X}: "{old_string}" -> "{new_string}"',
            )
            self.patches.append(patch)

            count += 1
            offset = idx + len(old_bytes)

        if count > 0:
            print(f"{Fore.GREEN}[+] Replaced {count} occurrence(s) of \"{old_string}\"{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] String \"{old_string}\" not found{Style.RESET_ALL}")

        return count

    def patch_jump(self, offset: int, jump_type: str = 'always', description: str = '') -> bool:
        """
        Modify a conditional jump instruction at the given offset.

        Supports x86/x86_64 short conditional jumps (one-byte opcode + one-byte offset).

        Args:
            offset: Offset of the conditional jump opcode
            jump_type: 'always' to make unconditional (JMP), 'nop' to NOP out
            description: Human-readable description

        Returns:
            True if the jump was patched successfully

        Raises:
            ValueError: If offset is out of range or opcode is not a known conditional jump
        """
        if offset < 0 or offset + 2 > len(self.data):
            raise ValueError(f"Offset 0x{offset:X} is out of range")

        opcode = self.data[offset]

        if opcode not in self.X86_JUMPS:
            raise ValueError(
                f"Byte at 0x{offset:X} (0x{opcode:02X}) is not a recognized conditional jump"
            )

        jump_name = self.X86_JUMPS[opcode]
        original = bytes(self.data[offset:offset + 2])

        if jump_type == 'always':
            # Replace with short JMP (0xEB + same offset)
            self.data[offset] = 0xEB
            new_bytes = bytes(self.data[offset:offset + 2])
            desc = description or f'Patched {jump_name} -> JMP at 0x{offset:X}'
        elif jump_type == 'nop':
            # NOP out both bytes
            self.data[offset] = 0x90
            self.data[offset + 1] = 0x90
            new_bytes = b'\x90\x90'
            desc = description or f'NOP\'d {jump_name} at 0x{offset:X}'
        else:
            raise ValueError(f"Unknown jump_type: {jump_type}. Use 'always' or 'nop'.")

        patch = Patch(
            offset=offset,
            original=original,
            patched=new_bytes,
            description=desc,
        )
        self.patches.append(patch)

        print(f"{Fore.GREEN}[+] {desc}{Style.RESET_ALL}")
        return True

    def find_pattern(self, pattern: bytes, start: int = 0) -> List[int]:
        """
        Find all occurrences of a byte pattern in the binary.

        Supports wildcard bytes using the b'??' notation. In the pattern,
        any byte position with value 0x3F3F (ascii '??') is treated as
        a wildcard that matches any byte.

        Args:
            pattern: Byte pattern to search for
            start: Offset to begin searching from

        Returns:
            List of offsets where the pattern was found
        """
        if not pattern:
            return []

        offsets: List[int] = []
        data_len = len(self.data)
        pat_len = len(pattern)

        # Simple exact match (no wildcards)
        # For patterns without '?' bytes, use fast bytearray.find
        if b'?' not in pattern:
            offset = start
            while True:
                idx = self.data.find(pattern, offset)
                if idx == -1:
                    break
                offsets.append(idx)
                offset = idx + 1
        else:
            # Wildcard matching: scan byte-by-byte
            for i in range(start, data_len - pat_len + 1):
                match = True
                for j in range(pat_len):
                    if pattern[j] == 0x3F:  # '?' character
                        continue  # Wildcard, always matches
                    if self.data[i + j] != pattern[j]:
                        match = False
                        break
                if match:
                    offsets.append(i)

        if offsets:
            print(f"{Fore.GREEN}[+] Pattern found at {len(offsets)} offset(s){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Pattern not found{Style.RESET_ALL}")

        return offsets

    def bypass_license_check(self) -> List[Dict]:
        """
        Auto-detect and attempt to patch common license/registration checks.

        Searches for license-related strings, locates nearby conditional
        jumps, and patches them to always pass.

        Returns:
            List of patch description dicts: {offset, type, description}
        """
        print(f"\n{Fore.YELLOW}[*] Attempting license check bypass...{Style.RESET_ALL}")
        results: List[Dict] = []

        for license_str in self.LICENSE_STRINGS:
            offsets = self.find_pattern(license_str)
            for offset in offsets:
                # Search for conditional jumps in the surrounding region
                # (within 256 bytes after the string reference)
                search_start = max(0, offset - 64)
                search_end = min(len(self.data), offset + 256)

                for i in range(search_start, search_end):
                    if self.data[i] in self.X86_JUMPS and i + 1 < len(self.data):
                        jump_name = self.X86_JUMPS[self.data[i]]
                        try:
                            self.patch_jump(i, jump_type='always',
                                            description=f'License bypass: {jump_name} near "{license_str.decode("ascii", errors="replace")}"')
                            results.append({
                                'offset': i,
                                'type': 'license_bypass',
                                'description': f'Patched {jump_name} at 0x{i:X} near license string at 0x{offset:X}',
                            })
                        except ValueError:
                            continue

        if results:
            print(f"{Fore.GREEN}[+] Applied {len(results)} license bypass patch(es){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No license checks found to bypass{Style.RESET_ALL}")

        return results

    def bypass_anti_debug(self) -> List[Dict]:
        """
        Find and NOP anti-debugging function calls.

        Locates references to known anti-debug APIs and NOPs the
        surrounding CALL instructions and return value checks.

        Returns:
            List of patch description dicts: {offset, type, description}
        """
        print(f"\n{Fore.YELLOW}[*] Attempting anti-debug bypass...{Style.RESET_ALL}")
        results: List[Dict] = []

        for target in self.ANTI_DEBUG_TARGETS:
            offsets = self.find_pattern(target)
            for offset in offsets:
                # Search backwards for CALL (0xE8) or CALL indirect (0xFF 0x15)
                search_start = max(0, offset - 128)
                for i in range(offset, search_start, -1):
                    # Direct CALL (E8 xx xx xx xx) = 5 bytes
                    if self.data[i] == 0xE8:
                        try:
                            self.nop_region(i, 5,
                                            description=f'Anti-debug bypass: NOP CALL to {target.decode("ascii", errors="replace")} at 0x{i:X}')
                            results.append({
                                'offset': i,
                                'type': 'anti_debug_bypass',
                                'description': f'NOP\'d CALL to {target.decode("ascii", errors="replace")} at 0x{i:X}',
                            })
                        except ValueError:
                            continue
                        break
                    # Indirect CALL (FF 15 xx xx xx xx) = 6 bytes
                    elif self.data[i] == 0xFF and i + 1 < len(self.data) and self.data[i + 1] == 0x15:
                        try:
                            self.nop_region(i, 6,
                                            description=f'Anti-debug bypass: NOP indirect CALL to {target.decode("ascii", errors="replace")} at 0x{i:X}')
                            results.append({
                                'offset': i,
                                'type': 'anti_debug_bypass',
                                'description': f'NOP\'d indirect CALL to {target.decode("ascii", errors="replace")} at 0x{i:X}',
                            })
                        except ValueError:
                            continue
                        break

        if results:
            print(f"{Fore.GREEN}[+] Applied {len(results)} anti-debug bypass(es){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No anti-debug calls found to bypass{Style.RESET_ALL}")

        return results

    def bypass_integrity_check(self) -> List[Dict]:
        """
        Find and NOP self-integrity / checksum verification routines.

        Searches for CRC32 constants, checksum strings, and hash
        comparison patterns and NOPs nearby conditional jumps.

        Returns:
            List of patch description dicts: {offset, type, description}
        """
        print(f"\n{Fore.YELLOW}[*] Attempting integrity check bypass...{Style.RESET_ALL}")
        results: List[Dict] = []

        # CRC32 polynomial constant (0xEDB88320)
        crc32_const = b'\x20\x83\xb8\xed'
        crc_offsets = self.find_pattern(crc32_const)
        for offset in crc_offsets:
            # Search for conditional jumps near the CRC usage
            search_end = min(len(self.data), offset + 256)
            for i in range(offset, search_end):
                if self.data[i] in self.X86_JUMPS and i + 1 < len(self.data):
                    jump_name = self.X86_JUMPS[self.data[i]]
                    try:
                        self.patch_jump(i, jump_type='nop',
                                        description=f'Integrity bypass: NOP {jump_name} near CRC32 at 0x{offset:X}')
                        results.append({
                            'offset': i,
                            'type': 'integrity_bypass',
                            'description': f'NOP\'d {jump_name} at 0x{i:X} near CRC32 constant',
                        })
                    except ValueError:
                        continue

        # String-based integrity indicators
        for indicator in self.INTEGRITY_INDICATORS:
            offsets = self.find_pattern(indicator)
            for offset in offsets:
                search_end = min(len(self.data), offset + 256)
                for i in range(offset, search_end):
                    if self.data[i] in self.X86_JUMPS and i + 1 < len(self.data):
                        jump_name = self.X86_JUMPS[self.data[i]]
                        try:
                            self.patch_jump(i, jump_type='nop',
                                            description=f'Integrity bypass: NOP {jump_name} near "{indicator.decode("ascii", errors="replace")}"')
                            results.append({
                                'offset': i,
                                'type': 'integrity_bypass',
                                'description': f'NOP\'d {jump_name} at 0x{i:X} near integrity string',
                            })
                        except ValueError:
                            continue

        if results:
            print(f"{Fore.GREEN}[+] Applied {len(results)} integrity bypass(es){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No integrity checks found to bypass{Style.RESET_ALL}")

        return results

    def save(self, output_path: str = None) -> str:
        """
        Write the patched binary to disk.

        Args:
            output_path: Destination path. Defaults to 'original.patched.ext'.

        Returns:
            Absolute path to the saved patched binary
        """
        if output_path is None:
            stem = self.binary_path.stem
            suffix = self.binary_path.suffix
            output_path = str(self.binary_path.parent / f'{stem}.patched{suffix}')

        output = Path(output_path).resolve()
        with open(output, 'wb') as f:
            f.write(self.data)

        print(f"{Fore.GREEN}[+] Patched binary saved: {output}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total patches applied: {len(self.patches)}{Style.RESET_ALL}")
        return str(output)

    def get_diff(self) -> List[Dict]:
        """
        Return a summary of all patches applied.

        Returns:
            List of dicts with keys: offset, hex_offset, original_bytes,
            patched_bytes, description
        """
        diff: List[Dict] = []

        for patch in self.patches:
            diff.append({
                'offset': patch.offset,
                'hex_offset': f'0x{patch.offset:08X}',
                'original_bytes': patch.original.hex(),
                'patched_bytes': patch.patched.hex(),
                'description': patch.description,
            })

        return diff

    def undo_all(self) -> None:
        """
        Restore the binary to its original state, reverting all patches.
        """
        self.data = bytearray(self.original)
        patch_count = len(self.patches)
        self.patches.clear()
        print(f"{Fore.GREEN}[+] Reverted all {patch_count} patches{Style.RESET_ALL}")

    def undo_last(self) -> bool:
        """
        Undo the most recently applied patch.

        Returns:
            True if a patch was undone, False if no patches exist
        """
        if not self.patches:
            print(f"{Fore.YELLOW}[!] No patches to undo{Style.RESET_ALL}")
            return False

        patch = self.patches.pop()
        self.data[patch.offset:patch.offset + len(patch.original)] = patch.original

        print(f"{Fore.GREEN}[+] Undid patch at 0x{patch.offset:X}: {patch.description}{Style.RESET_ALL}")
        return True
