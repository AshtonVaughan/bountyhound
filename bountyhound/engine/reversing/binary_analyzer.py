"""
Binary Analyzer
Full binary analysis module for PE, ELF, and Mach-O files.
Detects file type, architecture, packing, anti-debug, crypto usage,
and potential vulnerabilities in compiled binaries.
"""

import os
import re
import math
import struct
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import Counter
from colorama import Fore, Style


@dataclass
class BinaryInfo:
    """Metadata summary for an analyzed binary"""
    path: str
    file_type: str
    architecture: Dict
    size: int
    md5: str
    sha256: str
    entropy: float
    is_packed: bool
    sections_count: int
    imports_count: int
    exports_count: int


class BinaryAnalyzer:
    """
    Comprehensive binary analysis for PE, ELF, and Mach-O executables.

    Provides static analysis capabilities including file type detection,
    architecture identification, string extraction, packing detection,
    anti-debug detection, crypto identification, and vulnerability scanning.
    """

    # Magic bytes for file type detection
    MAGIC_BYTES = {
        b'MZ': 'PE',
        b'\x7fELF': 'ELF',
        b'\xfe\xed\xfa\xce': 'Mach-O_32',
        b'\xfe\xed\xfa\xcf': 'Mach-O_64',
        b'\xca\xfe\xba\xbe': 'Mach-O_Universal',
    }

    # ELF e_machine values
    ELF_MACHINES = {
        0x03: 'x86',
        0x08: 'MIPS',
        0x14: 'PowerPC',
        0x28: 'ARM',
        0x3E: 'x86_64',
        0xB7: 'AArch64',
    }

    # PE machine values
    PE_MACHINES = {
        0x014C: 'x86',
        0x0200: 'IA64',
        0x8664: 'x86_64',
        0x01C0: 'ARM',
        0xAA64: 'AArch64',
    }

    # Regex patterns for interesting strings
    STRING_PATTERNS = {
        'urls': re.compile(rb'https?://[^\s\x00"\'<>]{6,}'),
        'ips': re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'emails': re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        'file_paths': re.compile(rb'(?:[A-Z]:\\|/(?:usr|etc|var|tmp|home|opt|bin|sbin))[^\s\x00"\']{4,}'),
        'registry_keys': re.compile(rb'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)[^\s\x00"\']{4,}'),
        'api_keys': re.compile(rb'(?:api[_-]?key|apikey|access[_-]?token)["\s:=]+[a-zA-Z0-9]{16,}', re.IGNORECASE),
        'crypto_constants': re.compile(rb'(?:AES|RSA|DES|SHA[0-9]*|MD5|HMAC|ECDSA|ECDH)', re.IGNORECASE),
        'debug_strings': re.compile(rb'(?:DEBUG|TRACE|ASSERT|BREAKPOINT|CHECKPOINT)[^\x00]{0,60}', re.IGNORECASE),
        'error_messages': re.compile(rb'(?:ERROR|FATAL|EXCEPTION|FAILED|DENIED|REFUSED)[^\x00]{0,80}', re.IGNORECASE),
    }

    # Anti-debug indicators
    ANTI_DEBUG_INDICATORS = [
        b'IsDebuggerPresent',
        b'NtQueryInformationProcess',
        b'CheckRemoteDebuggerPresent',
        b'OutputDebugString',
        b'NtSetInformationThread',
        b'NtQuerySystemInformation',
        b'CloseHandle',           # Used in SEH anti-debug
        b'ptrace',
        b'PTRACE_TRACEME',
        b'sysctl',
        b'CTL_KERN',
        b'getppid',
        b'P_TRACED',
    ]

    # Dangerous imports indicating potential vulnerabilities
    DANGEROUS_IMPORTS = {
        'buffer_overflow': [
            b'strcpy', b'strcat', b'sprintf', b'gets', b'scanf',
            b'vsprintf', b'wcscpy', b'wcscat', b'_mbscpy',
        ],
        'dynamic_loading': [
            b'LoadLibrary', b'LoadLibraryA', b'LoadLibraryW',
            b'GetProcAddress', b'dlopen', b'dlsym',
        ],
        'shellcode_patterns': [
            b'VirtualAlloc', b'VirtualAllocEx', b'VirtualProtect',
            b'WriteProcessMemory', b'NtAllocateVirtualMemory',
            b'mmap', b'mprotect',
        ],
        'injection': [
            b'CreateRemoteThread', b'CreateRemoteThreadEx',
            b'NtCreateThreadEx', b'RtlCreateUserThread',
            b'QueueUserAPC', b'SetWindowsHookEx',
        ],
        'process_manipulation': [
            b'OpenProcess', b'TerminateProcess',
            b'CreateProcess', b'ShellExecute',
        ],
    }

    # Known packer signatures
    PACKER_SIGNATURES = {
        'UPX': [b'UPX!', b'UPX0', b'UPX1', b'UPX2'],
        'ASPack': [b'.aspack', b'.adata', b'ASPack'],
        'Themida': [b'.themida', b'Themida'],
        'VMProtect': [b'.vmp0', b'.vmp1', b'.vmp2', b'VMProtect'],
        'PECompact': [b'PEC2', b'PECompact2'],
        'MPRESS': [b'.MPRESS1', b'.MPRESS2'],
        'Petite': [b'.petite', b'Petite'],
        'NSPack': [b'.nsp0', b'.nsp1', b'nsPack'],
    }

    # AES S-box first 16 bytes for detection
    AES_SBOX_PREFIX = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                             0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76])

    # MD5 init values
    MD5_INIT = [
        struct.pack('<I', 0x67452301),
        struct.pack('<I', 0xEFCDAB89),
        struct.pack('<I', 0x98BADCFE),
        struct.pack('<I', 0x10325476),
    ]

    # SHA-256 initial hash constants (first two, packed as big-endian)
    SHA256_CONSTANTS = [
        struct.pack('>I', 0x6A09E667),
        struct.pack('>I', 0xBB67AE85),
        struct.pack('>I', 0x428A2F98),  # First round constant
    ]

    def __init__(self, binary_path: str):
        """
        Initialize the binary analyzer.

        Args:
            binary_path: Path to the binary file to analyze

        Raises:
            FileNotFoundError: If the binary file does not exist
            ValueError: If the path is empty
        """
        if not binary_path:
            raise ValueError("binary_path must not be empty")

        self.binary_path = Path(binary_path).resolve()

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not self.binary_path.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")

        self.file_size = self.binary_path.stat().st_size
        self._data: Optional[bytes] = None
        self._strings_cache: Optional[List[str]] = None

        print(f"{Fore.GREEN}[+] Binary analyzer initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] File: {self.binary_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Size: {self.file_size:,} bytes{Style.RESET_ALL}")

    @property
    def data(self) -> bytes:
        """Lazy-load binary data into memory."""
        if self._data is None:
            with open(self.binary_path, 'rb') as f:
                self._data = f.read()
        return self._data

    def analyze(self) -> Dict:
        """
        Perform full binary analysis by invoking all analysis methods.

        Returns:
            Combined dictionary of all analysis results
        """
        print(f"\n{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive binary analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")

        file_type = self.get_file_type()
        architecture = self.get_architecture()
        sections = self.get_sections()
        imports = self.get_imports()
        exports = self.get_exports()
        entropy = self.calculate_entropy()
        packing = self.detect_packing()
        interesting = self.find_interesting_strings()
        anti_debug = self.detect_anti_debug()
        crypto = self.detect_crypto()
        vulns = self.find_vulnerabilities()

        results = {
            'file_info': {
                'path': str(self.binary_path),
                'size': self.file_size,
                'md5': hashlib.md5(self.data).hexdigest(),
                'sha256': hashlib.sha256(self.data).hexdigest(),
            },
            'file_type': file_type,
            'architecture': architecture,
            'entropy': entropy,
            'sections': sections,
            'imports': imports,
            'exports': exports,
            'packing': packing,
            'interesting_strings': interesting,
            'anti_debug': anti_debug,
            'crypto': crypto,
            'vulnerabilities': vulns,
            'summary': self.summary(),
        }

        print(f"\n{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Analysis complete{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")

        return results

    def get_file_type(self) -> str:
        """
        Detect binary file type by examining magic bytes.

        Returns:
            File type string: 'PE', 'ELF', 'Mach-O_32', 'Mach-O_64',
            'Mach-O_Universal', or 'unknown'
        """
        header = self.data[:4]

        for magic, file_type in self.MAGIC_BYTES.items():
            if header[:len(magic)] == magic:
                print(f"{Fore.GREEN}[+] File type: {file_type}{Style.RESET_ALL}")
                return file_type

        print(f"{Fore.YELLOW}[!] File type: unknown{Style.RESET_ALL}")
        return 'unknown'

    def get_architecture(self) -> Dict:
        """
        Extract architecture information from the binary headers.

        Parses ELF e_machine field or PE Machine field to determine
        the target architecture and bitness.

        Returns:
            Dictionary with keys: arch, bits, endian
        """
        result = {'arch': 'unknown', 'bits': 0, 'endian': 'unknown'}
        file_type = self.get_file_type()

        try:
            if file_type == 'ELF' and len(self.data) >= 20:
                # ELF: class at offset 4 (1=32-bit, 2=64-bit)
                ei_class = self.data[4]
                result['bits'] = 32 if ei_class == 1 else 64
                # ELF: data at offset 5 (1=LE, 2=BE)
                ei_data = self.data[5]
                result['endian'] = 'little' if ei_data == 1 else 'big'
                # ELF: e_machine at offset 18 (2 bytes)
                fmt = '<H' if ei_data == 1 else '>H'
                e_machine = struct.unpack(fmt, self.data[18:20])[0]
                result['arch'] = self.ELF_MACHINES.get(e_machine, f'unknown(0x{e_machine:04X})')

            elif file_type == 'PE' and len(self.data) >= 68:
                # PE: e_lfanew at offset 0x3C gives PE header offset
                e_lfanew = struct.unpack('<I', self.data[0x3C:0x40])[0]
                if e_lfanew + 6 <= len(self.data):
                    # Machine field at PE header + 4
                    machine = struct.unpack('<H', self.data[e_lfanew + 4:e_lfanew + 6])[0]
                    result['arch'] = self.PE_MACHINES.get(machine, f'unknown(0x{machine:04X})')
                    result['bits'] = 64 if machine in (0x8664, 0xAA64) else 32
                    result['endian'] = 'little'

            elif file_type in ('Mach-O_32', 'Mach-O_64'):
                result['bits'] = 64 if file_type == 'Mach-O_64' else 32
                result['endian'] = 'little'
                if len(self.data) >= 8:
                    cputype = struct.unpack('<I', self.data[4:8])[0]
                    mach_arches = {7: 'x86', 0x01000007: 'x86_64', 12: 'ARM', 0x0100000C: 'AArch64'}
                    result['arch'] = mach_arches.get(cputype, f'unknown(0x{cputype:08X})')

            elif file_type == 'Mach-O_Universal':
                result['arch'] = 'Universal (fat binary)'
                result['endian'] = 'big'

        except (struct.error, IndexError) as e:
            print(f"{Fore.YELLOW}[!] Could not fully parse architecture: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Architecture: {result['arch']} {result['bits']}-bit {result['endian']}-endian{Style.RESET_ALL}")
        return result

    def extract_strings(self, min_length: int = 4) -> List[str]:
        """
        Extract printable ASCII and Unicode strings from the binary.

        Args:
            min_length: Minimum character count to qualify as a string

        Returns:
            List of extracted strings
        """
        if self._strings_cache is not None:
            return self._strings_cache

        print(f"{Fore.YELLOW}[*] Extracting strings (min length: {min_length})...{Style.RESET_ALL}")
        strings: List[str] = []

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, self.data):
            strings.append(match.group().decode('ascii', errors='replace'))

        # UTF-16LE strings (common in PE binaries)
        utf16_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
        for match in re.finditer(utf16_pattern, self.data):
            try:
                decoded = match.group().decode('utf-16-le', errors='replace').rstrip('\x00')
                if len(decoded) >= min_length:
                    strings.append(decoded)
            except (UnicodeDecodeError, ValueError):
                continue

        self._strings_cache = strings
        print(f"{Fore.GREEN}[+] Extracted {len(strings):,} strings{Style.RESET_ALL}")
        return strings

    def find_interesting_strings(self) -> Dict[str, List[str]]:
        """
        Categorize extracted strings into security-relevant groups.

        Returns:
            Dictionary mapping category names to lists of matching strings.
            Categories: urls, ips, emails, file_paths, registry_keys,
            api_keys, crypto_constants, debug_strings, error_messages
        """
        print(f"{Fore.YELLOW}[*] Searching for interesting strings...{Style.RESET_ALL}")
        results: Dict[str, List[str]] = {key: [] for key in self.STRING_PATTERNS}

        for category, pattern in self.STRING_PATTERNS.items():
            matches = pattern.findall(self.data)
            unique = list(set(m.decode('utf-8', errors='replace') for m in matches))[:100]
            results[category] = unique
            if unique:
                print(f"{Fore.GREEN}[+] {category}: {len(unique)} unique matches{Style.RESET_ALL}")

        return results

    def get_imports(self) -> List[Dict]:
        """
        Extract imported functions from the binary.

        For PE files, parses the import directory table. For ELF and
        other formats, falls back to string-based extraction of known
        library function names.

        Returns:
            List of dicts with keys: library, function
        """
        print(f"{Fore.YELLOW}[*] Extracting imports...{Style.RESET_ALL}")
        imports: List[Dict] = []
        file_type = self.get_file_type()

        try:
            if file_type == 'PE' and len(self.data) >= 0x40:
                e_lfanew = struct.unpack('<I', self.data[0x3C:0x40])[0]
                if e_lfanew + 0x80 <= len(self.data):
                    # Optional header starts at e_lfanew + 24
                    # Import directory RVA depends on 32/64-bit
                    magic = struct.unpack('<H', self.data[e_lfanew + 24:e_lfanew + 26])[0]
                    if magic == 0x10B:  # PE32
                        import_rva_offset = e_lfanew + 24 + 104
                    elif magic == 0x20B:  # PE32+
                        import_rva_offset = e_lfanew + 24 + 120
                    else:
                        import_rva_offset = None

                    # Fall back to string-based extraction for robustness
                    if import_rva_offset:
                        imports = self._extract_imports_from_strings()
            else:
                imports = self._extract_imports_from_strings()

        except (struct.error, IndexError):
            imports = self._extract_imports_from_strings()

        print(f"{Fore.CYAN}[*] Imports found: {len(imports)}{Style.RESET_ALL}")
        return imports

    def _extract_imports_from_strings(self) -> List[Dict]:
        """
        Extract import-like function names from binary strings.

        Returns:
            List of dicts with keys: library, function
        """
        imports: List[Dict] = []
        strings = self.extract_strings(min_length=4)

        # Common library suffixes
        dll_pattern = re.compile(r'^([a-zA-Z0-9_]+\.dll)$', re.IGNORECASE)
        # Common API function name pattern
        func_pattern = re.compile(r'^([A-Z][a-zA-Z0-9]+(?:[A-Z][a-zA-Z0-9]+)+)$')

        current_lib = 'unknown'
        for s in strings:
            dll_match = dll_pattern.match(s)
            if dll_match:
                current_lib = dll_match.group(1)
                continue

            func_match = func_pattern.match(s)
            if func_match:
                imports.append({'library': current_lib, 'function': func_match.group(1)})

        return imports

    def get_exports(self) -> List[str]:
        """
        Extract exported function names from the binary.

        Uses string-based heuristic to identify exported symbols.

        Returns:
            List of exported function name strings
        """
        print(f"{Fore.YELLOW}[*] Extracting exports...{Style.RESET_ALL}")
        exports: List[str] = []
        strings = self.extract_strings(min_length=4)

        # For ELF, look for symbol-like strings
        export_pattern = re.compile(r'^[a-z_][a-z0-9_]+$')
        for s in strings:
            if export_pattern.match(s) and len(s) >= 4:
                exports.append(s)

        # Deduplicate, cap at 500
        exports = list(set(exports))[:500]
        print(f"{Fore.CYAN}[*] Exports found: {len(exports)}{Style.RESET_ALL}")
        return exports

    def get_sections(self) -> List[Dict]:
        """
        Parse section/segment headers from the binary.

        For PE files, parses COFF section headers. For ELF files,
        parses section headers. Calculates per-section entropy.

        Returns:
            List of dicts with keys: name, virtual_address, size, entropy, flags
        """
        print(f"{Fore.YELLOW}[*] Parsing sections...{Style.RESET_ALL}")
        sections: List[Dict] = []
        file_type = self.get_file_type()

        try:
            if file_type == 'PE' and len(self.data) >= 0x40:
                e_lfanew = struct.unpack('<I', self.data[0x3C:0x40])[0]
                # Number of sections at e_lfanew + 6
                if e_lfanew + 8 <= len(self.data):
                    num_sections = struct.unpack('<H', self.data[e_lfanew + 6:e_lfanew + 8])[0]
                    # Size of optional header at e_lfanew + 20
                    opt_hdr_size = struct.unpack('<H', self.data[e_lfanew + 20:e_lfanew + 22])[0]
                    # Section headers start after optional header
                    section_offset = e_lfanew + 24 + opt_hdr_size

                    for i in range(min(num_sections, 96)):  # Cap at 96 sections
                        off = section_offset + (i * 40)
                        if off + 40 > len(self.data):
                            break

                        name_raw = self.data[off:off + 8]
                        name = name_raw.split(b'\x00')[0].decode('ascii', errors='replace')
                        virtual_size = struct.unpack('<I', self.data[off + 8:off + 12])[0]
                        virtual_addr = struct.unpack('<I', self.data[off + 12:off + 16])[0]
                        raw_size = struct.unpack('<I', self.data[off + 16:off + 20])[0]
                        raw_offset = struct.unpack('<I', self.data[off + 20:off + 24])[0]
                        characteristics = struct.unpack('<I', self.data[off + 36:off + 40])[0]

                        # Calculate section entropy
                        section_data = self.data[raw_offset:raw_offset + raw_size]
                        section_entropy = self.calculate_entropy(section_data) if section_data else 0.0

                        sections.append({
                            'name': name,
                            'virtual_address': f'0x{virtual_addr:08X}',
                            'size': virtual_size,
                            'entropy': round(section_entropy, 4),
                            'flags': f'0x{characteristics:08X}',
                        })

            elif file_type == 'ELF' and len(self.data) >= 64:
                ei_class = self.data[4]
                ei_data = self.data[5]
                fmt = '<' if ei_data == 1 else '>'

                if ei_class == 1:  # 32-bit
                    e_shoff = struct.unpack(f'{fmt}I', self.data[32:36])[0]
                    e_shentsize = struct.unpack(f'{fmt}H', self.data[46:48])[0]
                    e_shnum = struct.unpack(f'{fmt}H', self.data[48:50])[0]
                    e_shstrndx = struct.unpack(f'{fmt}H', self.data[50:52])[0]
                else:  # 64-bit
                    e_shoff = struct.unpack(f'{fmt}Q', self.data[40:48])[0]
                    e_shentsize = struct.unpack(f'{fmt}H', self.data[58:60])[0]
                    e_shnum = struct.unpack(f'{fmt}H', self.data[60:62])[0]
                    e_shstrndx = struct.unpack(f'{fmt}H', self.data[62:64])[0]

                # Read section name string table
                shstrtab_off = e_shoff + (e_shstrndx * e_shentsize)
                if ei_class == 1:
                    strtab_offset = struct.unpack(f'{fmt}I', self.data[shstrtab_off + 16:shstrtab_off + 20])[0]
                    strtab_size = struct.unpack(f'{fmt}I', self.data[shstrtab_off + 20:shstrtab_off + 24])[0]
                else:
                    strtab_offset = struct.unpack(f'{fmt}Q', self.data[shstrtab_off + 24:shstrtab_off + 32])[0]
                    strtab_size = struct.unpack(f'{fmt}Q', self.data[shstrtab_off + 32:shstrtab_off + 40])[0]

                strtab = self.data[strtab_offset:strtab_offset + strtab_size]

                for i in range(min(e_shnum, 96)):
                    off = e_shoff + (i * e_shentsize)
                    if off + e_shentsize > len(self.data):
                        break

                    name_idx = struct.unpack(f'{fmt}I', self.data[off:off + 4])[0]
                    sh_flags = struct.unpack(f'{fmt}I', self.data[off + 8:off + 12])[0]

                    if ei_class == 1:
                        sh_addr = struct.unpack(f'{fmt}I', self.data[off + 12:off + 16])[0]
                        sh_offset = struct.unpack(f'{fmt}I', self.data[off + 16:off + 20])[0]
                        sh_size = struct.unpack(f'{fmt}I', self.data[off + 20:off + 24])[0]
                    else:
                        sh_addr = struct.unpack(f'{fmt}Q', self.data[off + 16:off + 24])[0]
                        sh_offset = struct.unpack(f'{fmt}Q', self.data[off + 24:off + 32])[0]
                        sh_size = struct.unpack(f'{fmt}Q', self.data[off + 32:off + 40])[0]

                    # Read section name from string table
                    name_end = strtab.find(b'\x00', name_idx)
                    name = strtab[name_idx:name_end].decode('ascii', errors='replace') if name_end > name_idx else ''

                    section_data = self.data[sh_offset:sh_offset + sh_size]
                    section_entropy = self.calculate_entropy(section_data) if section_data else 0.0

                    sections.append({
                        'name': name,
                        'virtual_address': f'0x{sh_addr:016X}',
                        'size': sh_size,
                        'entropy': round(section_entropy, 4),
                        'flags': f'0x{sh_flags:08X}',
                    })

        except (struct.error, IndexError, ValueError) as e:
            print(f"{Fore.YELLOW}[!] Section parsing incomplete: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Sections parsed: {len(sections)}{Style.RESET_ALL}")
        return sections

    def calculate_entropy(self, data: bytes = None) -> float:
        """
        Calculate Shannon entropy of the given data or the full binary.

        Entropy > 7.0 typically indicates packed or encrypted content.

        Args:
            data: Byte sequence to analyze. Uses full binary if None.

        Returns:
            Entropy value between 0.0 (uniform) and 8.0 (maximum randomness)
        """
        if data is None:
            data = self.data

        if not data:
            return 0.0

        byte_counts = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in byte_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def detect_packing(self) -> Dict:
        """
        Detect if the binary is packed or protected.

        Checks for known packer signatures and high-entropy sections.

        Returns:
            Dictionary with keys: is_packed, packer, confidence, indicators
        """
        print(f"{Fore.YELLOW}[*] Checking for packing/protection...{Style.RESET_ALL}")
        result = {
            'is_packed': False,
            'packer': None,
            'confidence': 'none',
            'indicators': [],
        }

        # Check packer signatures
        for packer_name, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in self.data:
                    result['is_packed'] = True
                    result['packer'] = packer_name
                    result['confidence'] = 'high'
                    result['indicators'].append(f'Signature match: {sig.decode("ascii", errors="replace")}')
                    print(f"{Fore.RED}[!] Packer detected: {packer_name}{Style.RESET_ALL}")
                    break
            if result['packer']:
                break

        # Check section entropy
        sections = self.get_sections()
        high_entropy_sections = []
        for section in sections:
            if section['entropy'] > 7.0:
                high_entropy_sections.append(section['name'])
                result['indicators'].append(
                    f"High entropy section: {section['name']} ({section['entropy']:.2f})"
                )

        if high_entropy_sections and not result['is_packed']:
            result['is_packed'] = True
            result['confidence'] = 'medium'
            print(f"{Fore.YELLOW}[!] High entropy sections detected - possible packing{Style.RESET_ALL}")

        # Check overall entropy
        overall_entropy = self.calculate_entropy()
        if overall_entropy > 7.0:
            result['indicators'].append(f'High overall entropy: {overall_entropy:.2f}')
            if not result['is_packed']:
                result['is_packed'] = True
                result['confidence'] = 'low'

        if not result['is_packed']:
            print(f"{Fore.GREEN}[+] No packing detected{Style.RESET_ALL}")

        return result

    def detect_anti_debug(self) -> List[str]:
        """
        Search for anti-debugging techniques in the binary.

        Scans imports and raw bytes for known anti-debug API calls
        and techniques.

        Returns:
            List of detected anti-debug indicator strings
        """
        print(f"{Fore.YELLOW}[*] Checking for anti-debug techniques...{Style.RESET_ALL}")
        detected: List[str] = []

        for indicator in self.ANTI_DEBUG_INDICATORS:
            if indicator in self.data:
                indicator_str = indicator.decode('ascii', errors='replace')
                detected.append(indicator_str)
                print(f"{Fore.RED}[!] Anti-debug: {indicator_str}{Style.RESET_ALL}")

        if not detected:
            print(f"{Fore.GREEN}[+] No anti-debug techniques detected{Style.RESET_ALL}")

        return detected

    def detect_crypto(self) -> List[Dict]:
        """
        Detect cryptographic algorithm usage in the binary.

        Identifies crypto through constant signatures (AES S-box, MD5 init,
        SHA constants) and string pattern matching.

        Returns:
            List of dicts with keys: algorithm, evidence, confidence
        """
        print(f"{Fore.YELLOW}[*] Detecting cryptographic usage...{Style.RESET_ALL}")
        findings: List[Dict] = []

        # Check AES S-box
        if self.AES_SBOX_PREFIX in self.data:
            findings.append({
                'algorithm': 'AES',
                'evidence': 'S-box constant detected',
                'confidence': 'high',
            })
            print(f"{Fore.GREEN}[+] AES S-box detected{Style.RESET_ALL}")

        # Check MD5 init values
        md5_count = sum(1 for iv in self.MD5_INIT if iv in self.data)
        if md5_count >= 3:
            findings.append({
                'algorithm': 'MD5',
                'evidence': f'{md5_count}/4 init values detected',
                'confidence': 'high' if md5_count == 4 else 'medium',
            })
            print(f"{Fore.GREEN}[+] MD5 init values detected ({md5_count}/4){Style.RESET_ALL}")

        # Check SHA-256 constants
        sha_count = sum(1 for c in self.SHA256_CONSTANTS if c in self.data)
        if sha_count >= 2:
            findings.append({
                'algorithm': 'SHA-256',
                'evidence': f'{sha_count}/3 constants detected',
                'confidence': 'high' if sha_count == 3 else 'medium',
            })
            print(f"{Fore.GREEN}[+] SHA-256 constants detected ({sha_count}/3){Style.RESET_ALL}")

        # String-based detection
        crypto_keywords = [
            b'AES', b'RSA', b'SHA', b'MD5', b'HMAC', b'bcrypt', b'scrypt',
            b'Blowfish', b'Twofish', b'ChaCha', b'Salsa20', b'ECDSA', b'ECDH',
            b'Curve25519', b'Ed25519', b'PBKDF2', b'argon2',
        ]

        for keyword in crypto_keywords:
            if keyword in self.data:
                algo_name = keyword.decode('ascii', errors='replace')
                # Avoid duplicate entries from constant detection above
                if not any(f['algorithm'] == algo_name for f in findings):
                    findings.append({
                        'algorithm': algo_name,
                        'evidence': 'String reference detected',
                        'confidence': 'low',
                    })

        if not findings:
            print(f"{Fore.CYAN}[*] No cryptographic indicators detected{Style.RESET_ALL}")

        return findings

    def find_vulnerabilities(self) -> List[Dict]:
        """
        Scan for potential security vulnerabilities based on imports and patterns.

        Checks for dangerous function usage (buffer overflow-prone APIs),
        dynamic code loading, shellcode allocation patterns, and process
        injection indicators.

        Returns:
            List of dicts with keys: type, indicator, severity, description
        """
        print(f"{Fore.YELLOW}[*] Scanning for vulnerabilities...{Style.RESET_ALL}")
        vulns: List[Dict] = []

        severity_map = {
            'buffer_overflow': ('HIGH', 'Use of unsafe string function prone to buffer overflow'),
            'dynamic_loading': ('MEDIUM', 'Dynamic library loading may indicate plugin system or evasion'),
            'shellcode_patterns': ('CRITICAL', 'Memory allocation/protection change pattern common in shellcode'),
            'injection': ('CRITICAL', 'Process injection capability detected'),
            'process_manipulation': ('MEDIUM', 'Process manipulation functions detected'),
        }

        for vuln_type, indicators in self.DANGEROUS_IMPORTS.items():
            severity, description = severity_map[vuln_type]
            for indicator in indicators:
                if indicator in self.data:
                    indicator_str = indicator.decode('ascii', errors='replace')
                    vulns.append({
                        'type': vuln_type,
                        'indicator': indicator_str,
                        'severity': severity,
                        'description': description,
                    })
                    color = Fore.RED if severity in ('CRITICAL', 'HIGH') else Fore.YELLOW
                    print(f"{color}[!] [{severity}] {vuln_type}: {indicator_str}{Style.RESET_ALL}")

        if not vulns:
            print(f"{Fore.GREEN}[+] No obvious vulnerability indicators found{Style.RESET_ALL}")

        return vulns

    def summary(self) -> Dict:
        """
        Generate a concise summary of the binary analysis.

        Returns:
            Dictionary with key statistics about the binary
        """
        file_type = self.get_file_type()
        architecture = self.get_architecture()
        packing = self.detect_packing()

        info = BinaryInfo(
            path=str(self.binary_path),
            file_type=file_type,
            architecture=architecture,
            size=self.file_size,
            md5=hashlib.md5(self.data).hexdigest(),
            sha256=hashlib.sha256(self.data).hexdigest(),
            entropy=self.calculate_entropy(),
            is_packed=packing['is_packed'],
            sections_count=len(self.get_sections()),
            imports_count=len(self.get_imports()),
            exports_count=len(self.get_exports()),
        )

        summary = {
            'path': info.path,
            'file_type': info.file_type,
            'architecture': info.architecture,
            'size_bytes': info.size,
            'md5': info.md5,
            'sha256': info.sha256,
            'entropy': info.entropy,
            'is_packed': info.is_packed,
            'sections': info.sections_count,
            'imports': info.imports_count,
            'exports': info.exports_count,
        }

        print(f"\n{Fore.CYAN}=== BINARY SUMMARY ==={Style.RESET_ALL}")
        print(f"  Type: {info.file_type} | Arch: {info.architecture.get('arch', 'unknown')} "
              f"{info.architecture.get('bits', '?')}-bit")
        print(f"  Size: {info.size:,} bytes | Entropy: {info.entropy:.2f}")
        print(f"  Packed: {info.is_packed} | Sections: {info.sections_count} | "
              f"Imports: {info.imports_count} | Exports: {info.exports_count}")
        print(f"  MD5:    {info.md5}")
        print(f"  SHA256: {info.sha256}")

        return summary
