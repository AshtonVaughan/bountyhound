"""
Firmware Analyzer
Extract strings, detect encryption, find credentials, and analyze firmware binaries
"""

import os
import re
import subprocess
import hashlib
import math
from typing import List, Dict, Optional, Set, Tuple
from colorama import Fore, Style
from dataclasses import dataclass
from collections import Counter
import struct


@dataclass
class FirmwareFinding:
    """Represents a firmware security finding"""
    severity: str
    title: str
    description: str
    evidence: str
    offset: Optional[int] = None
    timestamp: Optional[float] = None


class FirmwareAnalyzer:
    """Firmware binary analysis and security testing"""

    # Common credential patterns
    CREDENTIAL_PATTERNS = {
        'password': re.compile(rb'(?i)(password|passwd|pwd)["\s:=]+([^\s\x00]{4,})', re.IGNORECASE),
        'api_key': re.compile(rb'(?i)(api[_-]?key|apikey)["\s:=]+([a-zA-Z0-9]{16,})', re.IGNORECASE),
        'secret': re.compile(rb'(?i)(secret|token)["\s:=]+([a-zA-Z0-9+/]{16,})', re.IGNORECASE),
        'private_key': re.compile(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        'aws_key': re.compile(rb'AKIA[0-9A-Z]{16}'),
        'jwt': re.compile(rb'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    }

    # Common URL patterns
    URL_PATTERNS = {
        'http': re.compile(rb'https?://[^\s\x00"\'<>]{10,}'),
        'ip_address': re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        's3_bucket': re.compile(rb's3://[a-z0-9.-]+'),
        'domain': re.compile(rb'(?:[a-z0-9-]+\.)+[a-z]{2,}', re.IGNORECASE),
    }

    # Common backdoor patterns
    BACKDOOR_PATTERNS = [
        rb'/etc/shadow',
        rb'/etc/passwd',
        rb'telnetd',
        rb'sshd',
        rb'nc -l',
        rb'bash -i',
        rb'/bin/sh',
        rb'system\(',
        rb'exec\(',
        rb'popen\(',
        rb'backdoor',
        rb'debug_mode',
        rb'test_mode',
    ]

    # Common file system signatures
    FS_SIGNATURES = {
        b'hsqs': 'SquashFS',
        b'\x85\x19': 'JFFS2',
        b'UBI#': 'UBIFS',
        b'\x1f\x8b': 'GZIP',
        b'\x42\x5a': 'BZIP2',
        b'\xfd7zXZ': 'XZ',
        b'Rar!': 'RAR',
        b'PK\x03\x04': 'ZIP',
    }

    def __init__(self, firmware_path: str):
        """
        Initialize firmware analyzer.

        Args:
            firmware_path: Path to firmware binary file
        """
        self.firmware_path = firmware_path
        self.findings = []
        self.strings_cache = None
        self.file_size = os.path.getsize(firmware_path) if os.path.exists(firmware_path) else 0

        print(f"{Fore.GREEN}[+] Firmware analyzer initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] File: {firmware_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Size: {self.file_size:,} bytes{Style.RESET_ALL}")

    def extract_strings(self, min_length: int = 4, max_strings: int = 10000) -> List[bytes]:
        """
        Extract printable strings from firmware binary.

        Args:
            min_length: Minimum string length (default: 4)
            max_strings: Maximum strings to extract (default: 10000)

        Returns:
            List of extracted byte strings
        """
        if self.strings_cache:
            return self.strings_cache

        print(f"\n{Fore.YELLOW}[*] Extracting strings (min length: {min_length})...{Style.RESET_ALL}")
        strings = []

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            # Extract ASCII strings
            pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
            matches = re.findall(pattern, data)

            strings = matches[:max_strings]
            self.strings_cache = strings

            print(f"{Fore.GREEN}[+] Extracted {len(strings):,} strings{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting strings: {e}{Style.RESET_ALL}")

        return strings

    def calculate_entropy(self, block_size: int = 1024) -> float:
        """
        Calculate Shannon entropy of firmware to detect encryption/compression.

        Args:
            block_size: Size of blocks to analyze (default: 1024)

        Returns:
            Average entropy (0-8, where 8 is maximum randomness)
        """
        print(f"\n{Fore.YELLOW}[*] Calculating entropy...{Style.RESET_ALL}")

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            if len(data) == 0:
                return 0.0

            # Calculate entropy
            byte_counts = Counter(data)
            entropy = 0.0

            for count in byte_counts.values():
                probability = count / len(data)
                if probability > 0:
                    entropy -= probability * math.log2(probability)

            print(f"{Fore.CYAN}[*] Entropy: {entropy:.2f}/8.00{Style.RESET_ALL}")

            # Check for encryption
            if entropy > 7.5:
                finding = FirmwareFinding(
                    severity='MEDIUM',
                    title='High Entropy Detected',
                    description='Firmware appears to be encrypted or compressed (entropy > 7.5)',
                    evidence=f'Entropy: {entropy:.2f}/8.00'
                )
                self.findings.append(finding)
                print(f"{Fore.YELLOW}[!] High entropy suggests encryption/compression{Style.RESET_ALL}")

            return entropy

        except Exception as e:
            print(f"{Fore.RED}[!] Error calculating entropy: {e}{Style.RESET_ALL}")
            return 0.0

    def find_credentials(self) -> List[FirmwareFinding]:
        """
        Search for hardcoded credentials in firmware.

        Returns:
            List of credential findings
        """
        print(f"\n{Fore.YELLOW}[*] Searching for hardcoded credentials...{Style.RESET_ALL}")
        findings = []

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
                matches = pattern.finditer(data)

                for match in matches:
                    offset = match.start()
                    evidence = match.group(0)[:100]  # Limit evidence length

                    finding = FirmwareFinding(
                        severity='HIGH',
                        title=f'Hardcoded Credential: {cred_type.replace("_", " ").title()}',
                        description=f'Found {cred_type} pattern in firmware',
                        evidence=evidence.decode('utf-8', errors='replace'),
                        offset=offset
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    print(f"{Fore.RED}[!] Found {cred_type} at offset {hex(offset)}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error searching credentials: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Credential findings: {len(findings)}{Style.RESET_ALL}")
        return findings

    def find_urls(self) -> Dict[str, List[str]]:
        """
        Extract URLs and network endpoints from firmware.

        Returns:
            Dictionary mapping URL types to lists of found URLs
        """
        print(f"\n{Fore.YELLOW}[*] Extracting URLs and endpoints...{Style.RESET_ALL}")
        results = {key: [] for key in self.URL_PATTERNS.keys()}

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            for url_type, pattern in self.URL_PATTERNS.items():
                matches = pattern.findall(data)
                unique_urls = list(set(matches))[:50]  # Limit to 50 unique URLs per type

                results[url_type] = [
                    url.decode('utf-8', errors='replace')
                    for url in unique_urls
                ]

                if unique_urls:
                    print(f"{Fore.GREEN}[+] Found {len(unique_urls)} {url_type} entries{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting URLs: {e}{Style.RESET_ALL}")

        return results

    def detect_backdoors(self) -> List[FirmwareFinding]:
        """
        Search for backdoor indicators in firmware.

        Returns:
            List of backdoor findings
        """
        print(f"\n{Fore.YELLOW}[*] Searching for backdoor indicators...{Style.RESET_ALL}")
        findings = []

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            for pattern in self.BACKDOOR_PATTERNS:
                if pattern in data:
                    offset = data.find(pattern)
                    context_start = max(0, offset - 50)
                    context_end = min(len(data), offset + 50)
                    context = data[context_start:context_end]

                    finding = FirmwareFinding(
                        severity='CRITICAL',
                        title='Potential Backdoor Pattern Detected',
                        description=f'Found suspicious pattern: {pattern.decode("utf-8", errors="replace")}',
                        evidence=context.decode('utf-8', errors='replace'),
                        offset=offset
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    print(f"{Fore.RED}[!!!] Backdoor pattern at offset {hex(offset)}: {pattern[:30]}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting backdoors: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] Backdoor findings: {len(findings)}{Style.RESET_ALL}")
        return findings

    def identify_filesystems(self) -> List[Tuple[int, str]]:
        """
        Identify embedded file system signatures.

        Returns:
            List of tuples (offset, filesystem_type)
        """
        print(f"\n{Fore.YELLOW}[*] Identifying embedded file systems...{Style.RESET_ALL}")
        filesystems = []

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            for signature, fs_type in self.FS_SIGNATURES.items():
                offset = 0
                while True:
                    offset = data.find(signature, offset)
                    if offset == -1:
                        break

                    filesystems.append((offset, fs_type))
                    print(f"{Fore.GREEN}[+] Found {fs_type} at offset {hex(offset)}{Style.RESET_ALL}")

                    finding = FirmwareFinding(
                        severity='INFO',
                        title=f'Embedded Filesystem: {fs_type}',
                        description=f'Found {fs_type} signature in firmware',
                        evidence=f'Offset: {hex(offset)}',
                        offset=offset
                    )
                    self.findings.append(finding)

                    offset += len(signature)

        except Exception as e:
            print(f"{Fore.RED}[!] Error identifying filesystems: {e}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}[*] File systems found: {len(filesystems)}{Style.RESET_ALL}")
        return filesystems

    def extract_with_binwalk(self, output_dir: Optional[str] = None) -> bool:
        """
        Use binwalk to extract file systems (requires binwalk installed).

        Args:
            output_dir: Output directory for extracted files

        Returns:
            True if extraction succeeded
        """
        print(f"\n{Fore.YELLOW}[*] Attempting binwalk extraction...{Style.RESET_ALL}")

        try:
            # Check if binwalk is installed
            result = subprocess.run(
                ['binwalk', '--version'],
                capture_output=True,
                timeout=5
            )

            if result.returncode != 0:
                print(f"{Fore.YELLOW}[!] binwalk not installed{Style.RESET_ALL}")
                return False

            # Run binwalk extraction
            cmd = ['binwalk', '-e']
            if output_dir:
                cmd.extend(['-C', output_dir])
            cmd.append(self.firmware_path)

            print(f"{Fore.CYAN}[*] Running: {' '.join(cmd)}{Style.RESET_ALL}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=120,
                text=True
            )

            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Extraction complete{Style.RESET_ALL}")
                print(result.stdout)
                return True
            else:
                print(f"{Fore.RED}[!] Extraction failed{Style.RESET_ALL}")
                print(result.stderr)
                return False

        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] binwalk timeout{Style.RESET_ALL}")
            return False
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] binwalk not found in PATH{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error running binwalk: {e}{Style.RESET_ALL}")
            return False

    def calculate_hash(self) -> Dict[str, str]:
        """
        Calculate cryptographic hashes of firmware.

        Returns:
            Dictionary of hash algorithm to hash value
        """
        print(f"\n{Fore.YELLOW}[*] Calculating hashes...{Style.RESET_ALL}")
        hashes = {}

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()

            for algo, hash_value in hashes.items():
                print(f"{Fore.CYAN}[*] {algo.upper()}: {hash_value}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error calculating hashes: {e}{Style.RESET_ALL}")

        return hashes

    def analyze_architecture(self) -> Optional[str]:
        """
        Attempt to detect firmware architecture from magic bytes.

        Returns:
            Detected architecture or None
        """
        print(f"\n{Fore.YELLOW}[*] Detecting architecture...{Style.RESET_ALL}")

        architectures = {
            b'\x7fELF\x01\x01': 'ELF 32-bit LSB',
            b'\x7fELF\x01\x02': 'ELF 32-bit MSB',
            b'\x7fELF\x02\x01': 'ELF 64-bit LSB',
            b'\x7fELF\x02\x02': 'ELF 64-bit MSB',
            b'MZ': 'PE/COFF (Windows)',
            b'\xfe\xed\xfa\xce': 'Mach-O 32-bit',
            b'\xfe\xed\xfa\xcf': 'Mach-O 64-bit',
        }

        try:
            with open(self.firmware_path, 'rb') as f:
                header = f.read(16)

            for magic, arch in architectures.items():
                if header.startswith(magic):
                    print(f"{Fore.GREEN}[+] Architecture: {arch}{Style.RESET_ALL}")
                    return arch

            print(f"{Fore.YELLOW}[!] Architecture not detected{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting architecture: {e}{Style.RESET_ALL}")

        return None

    def comprehensive_analysis(self) -> Dict:
        """
        Perform comprehensive firmware analysis.

        Returns:
            Dictionary containing all analysis results
        """
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Starting comprehensive firmware analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        results = {
            'file_info': {
                'path': self.firmware_path,
                'size': self.file_size,
            },
            'hashes': self.calculate_hash(),
            'architecture': self.analyze_architecture(),
            'entropy': self.calculate_entropy(),
            'filesystems': self.identify_filesystems(),
            'strings': self.extract_strings(min_length=6, max_strings=1000),
            'urls': self.find_urls(),
            'credentials': self.find_credentials(),
            'backdoors': self.detect_backdoors(),
            'findings': self.findings,
        }

        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Analysis complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total findings: {len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

        return results

    def get_findings_summary(self) -> Dict:
        """
        Get summary of all findings.

        Returns:
            Dictionary with findings statistics
        """
        critical = sum(1 for f in self.findings if f.severity == 'CRITICAL')
        high = sum(1 for f in self.findings if f.severity == 'HIGH')
        medium = sum(1 for f in self.findings if f.severity == 'MEDIUM')
        low = sum(1 for f in self.findings if f.severity == 'LOW')
        info = sum(1 for f in self.findings if f.severity == 'INFO')

        return {
            'total': len(self.findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info,
            'findings': self.findings
        }
