"""
Decompiler
Integration with decompilation and disassembly tools including
Ghidra, radare2, rizin, and objdump for binary reverse engineering.
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from colorama import Fore, Style


@dataclass
class FunctionInfo:
    """Represents a discovered function in the binary"""
    name: str
    address: str
    size: int = 0
    category: Optional[str] = None


class Decompiler:
    """
    Decompilation and disassembly interface for binary analysis.

    Wraps external tools (radare2, rizin, Ghidra, objdump) to provide
    function listing, decompilation, cross-reference lookup, and
    control flow analysis. Automatically detects available tools.
    """

    # Safe path pattern: alphanumeric, hyphens, underscores, dots, slashes, spaces, colons (drive letters)
    SAFE_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9\-_./\\\s:]+$')

    # Function name patterns for targeted searches
    CRYPTO_FUNCTION_PATTERNS = re.compile(
        r'(?i)(encrypt|decrypt|hash|sign|verify|aes|rsa|sha|md5|hmac|cipher|key_gen|'
        r'keygen|pbkdf|scrypt|bcrypt|chacha|salsa|ecdsa|ecdh|curve25519|ed25519|'
        r'ssl_|tls_|crypto_|EVP_|RAND_)',
    )

    AUTH_FUNCTION_PATTERNS = re.compile(
        r'(?i)(login|auth|verify|password|passwd|token|session|license|register|'
        r'validate|check_key|check_license|check_serial|activate|deactivate|'
        r'is_licensed|is_registered|is_trial|is_expired|validate_key|serial_check|'
        r'check_password|verify_token|authenticate|authorize|grant_access)',
    )

    def __init__(self, binary_path: str):
        """
        Initialize the decompiler with a target binary.

        Args:
            binary_path: Path to the binary file to analyze

        Raises:
            FileNotFoundError: If the binary does not exist
            ValueError: If the path contains unsafe characters
        """
        if not binary_path:
            raise ValueError("binary_path must not be empty")

        # Validate path against injection
        if not self.SAFE_PATH_PATTERN.match(binary_path):
            raise ValueError(
                f"Path contains unsafe characters: {binary_path}. "
                "Only alphanumeric, hyphens, underscores, dots, and slashes are allowed."
            )

        self.binary_path = Path(binary_path).resolve()

        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if not self.binary_path.is_file():
            raise ValueError(f"Path is not a file: {binary_path}")

        self.available_tools: Dict[str, str] = {}
        self._detect_tools()

        print(f"{Fore.GREEN}[+] Decompiler initialized{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Binary: {self.binary_path}{Style.RESET_ALL}")
        if self.available_tools:
            tools_str = ', '.join(self.available_tools.keys())
            print(f"{Fore.CYAN}[*] Available tools: {tools_str}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No decompilation tools found in PATH{Style.RESET_ALL}")

    def _detect_tools(self) -> Dict[str, str]:
        """
        Detect which reverse engineering tools are installed on the system.

        Checks for radare2, rizin, Ghidra headless analyzer, objdump,
        and the strings utility via shutil.which().

        Returns:
            Dictionary mapping tool names to their executable paths
        """
        tool_executables = {
            'radare2': 'r2',
            'rizin': 'rz',
            'ghidra': 'analyzeHeadless',
            'objdump': 'objdump',
            'strings': 'strings',
        }

        for tool_name, executable in tool_executables.items():
            path = shutil.which(executable)
            if path:
                self.available_tools[tool_name] = path

        return self.available_tools

    def _run_command(self, cmd: List[str], timeout: int = 60) -> Optional[str]:
        """
        Execute a subprocess command safely with timeout.

        Args:
            cmd: Command and arguments as a list
            timeout: Maximum execution time in seconds

        Returns:
            stdout output as string, or None on failure
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"{Fore.YELLOW}[!] Command returned non-zero: {result.stderr[:200]}{Style.RESET_ALL}")
                return result.stdout if result.stdout else None
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] Command timed out after {timeout}s{Style.RESET_ALL}")
            return None
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Tool not found: {cmd[0]}{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Command error: {e}{Style.RESET_ALL}")
            return None

    def decompile_function(self, function_name: str) -> str:
        """
        Decompile or disassemble a specific function from the binary.

        Tries radare2 first (with pseudo-decompilation), then falls back
        to rizin, then to objdump disassembly.

        Args:
            function_name: Name of the function to decompile

        Returns:
            Decompiled/disassembled output as a string, or error message
        """
        print(f"{Fore.YELLOW}[*] Decompiling function: {function_name}{Style.RESET_ALL}")

        # Sanitize function name
        if not re.match(r'^[a-zA-Z0-9_.@]+$', function_name):
            return f"Error: Invalid function name: {function_name}"

        binary = str(self.binary_path)

        # Try radare2
        if 'radare2' in self.available_tools:
            r2_path = self.available_tools['radare2']
            output = self._run_command([
                r2_path, '-q', '-c',
                f'aaa; pdf @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                print(f"{Fore.GREEN}[+] Decompiled via radare2{Style.RESET_ALL}")
                return output

        # Try rizin
        if 'rizin' in self.available_tools:
            rz_path = self.available_tools['rizin']
            output = self._run_command([
                rz_path, '-q', '-c',
                f'aaa; pdf @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                print(f"{Fore.GREEN}[+] Decompiled via rizin{Style.RESET_ALL}")
                return output

        # Fallback to objdump
        if 'objdump' in self.available_tools:
            objdump_path = self.available_tools['objdump']
            output = self._run_command([
                objdump_path, '-d', binary,
            ], timeout=120)
            if output:
                # Extract function section from full disassembly
                pattern = re.compile(
                    rf'<{re.escape(function_name)}>:.*?(?=\n\n|\Z)',
                    re.DOTALL,
                )
                match = pattern.search(output)
                if match:
                    print(f"{Fore.GREEN}[+] Disassembled via objdump{Style.RESET_ALL}")
                    return match.group(0)

        return f"Error: Could not decompile function '{function_name}'. No suitable tool available."

    def list_functions(self) -> List[Dict]:
        """
        List all functions discovered in the binary.

        Uses radare2 or rizin for analysis, falling back to objdump
        symbol table parsing.

        Returns:
            List of dicts with keys: name, address, size
        """
        print(f"{Fore.YELLOW}[*] Listing functions...{Style.RESET_ALL}")
        functions: List[Dict] = []
        binary = str(self.binary_path)

        # Try radare2
        if 'radare2' in self.available_tools:
            r2_path = self.available_tools['radare2']
            output = self._run_command([
                r2_path, '-q', '-c', 'aaa; afl', binary,
            ], timeout=120)
            if output:
                for line in output.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        functions.append({
                            'address': parts[0],
                            'size': int(parts[2]) if parts[2].isdigit() else 0,
                            'name': parts[-1],
                        })
                if functions:
                    print(f"{Fore.GREEN}[+] Found {len(functions)} functions via radare2{Style.RESET_ALL}")
                    return functions

        # Try rizin
        if 'rizin' in self.available_tools:
            rz_path = self.available_tools['rizin']
            output = self._run_command([
                rz_path, '-q', '-c', 'aaa; afl', binary,
            ], timeout=120)
            if output:
                for line in output.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 4:
                        functions.append({
                            'address': parts[0],
                            'size': int(parts[2]) if parts[2].isdigit() else 0,
                            'name': parts[-1],
                        })
                if functions:
                    print(f"{Fore.GREEN}[+] Found {len(functions)} functions via rizin{Style.RESET_ALL}")
                    return functions

        # Fallback to objdump symbol table
        if 'objdump' in self.available_tools:
            objdump_path = self.available_tools['objdump']
            output = self._run_command([
                objdump_path, '-t', binary,
            ])
            if output:
                # Parse objdump symbol table: address flags section alignment name
                func_pattern = re.compile(r'^([0-9a-fA-F]+)\s+.*\sF\s+\.\w+\s+([0-9a-fA-F]+)\s+(.+)$')
                for line in output.strip().split('\n'):
                    match = func_pattern.match(line.strip())
                    if match:
                        functions.append({
                            'address': f'0x{match.group(1)}',
                            'size': int(match.group(2), 16),
                            'name': match.group(3).strip(),
                        })
                if functions:
                    print(f"{Fore.GREEN}[+] Found {len(functions)} functions via objdump{Style.RESET_ALL}")
                    return functions

        print(f"{Fore.YELLOW}[!] No functions found (no suitable tool available){Style.RESET_ALL}")
        return functions

    def get_xrefs(self, function_name: str) -> List[str]:
        """
        Get cross-references to a specific function.

        Uses radare2 or rizin to find all locations that call or
        reference the named function.

        Args:
            function_name: Name of the function to find references to

        Returns:
            List of cross-reference strings (caller address and context)
        """
        print(f"{Fore.YELLOW}[*] Getting xrefs for: {function_name}{Style.RESET_ALL}")

        if not re.match(r'^[a-zA-Z0-9_.@]+$', function_name):
            print(f"{Fore.RED}[!] Invalid function name{Style.RESET_ALL}")
            return []

        binary = str(self.binary_path)
        xrefs: List[str] = []

        # Try radare2
        if 'radare2' in self.available_tools:
            r2_path = self.available_tools['radare2']
            output = self._run_command([
                r2_path, '-q', '-c',
                f'aaa; axt @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                xrefs = [line.strip() for line in output.strip().split('\n') if line.strip()]
                print(f"{Fore.GREEN}[+] Found {len(xrefs)} xrefs via radare2{Style.RESET_ALL}")
                return xrefs

        # Try rizin
        if 'rizin' in self.available_tools:
            rz_path = self.available_tools['rizin']
            output = self._run_command([
                rz_path, '-q', '-c',
                f'aaa; axt @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                xrefs = [line.strip() for line in output.strip().split('\n') if line.strip()]
                print(f"{Fore.GREEN}[+] Found {len(xrefs)} xrefs via rizin{Style.RESET_ALL}")
                return xrefs

        print(f"{Fore.YELLOW}[!] No xrefs found (requires radare2 or rizin){Style.RESET_ALL}")
        return xrefs

    def decompile_ghidra(self, output_dir: str = None) -> str:
        """
        Run Ghidra headless analysis and decompilation on the binary.

        Requires Ghidra's analyzeHeadless to be in PATH. Creates a
        temporary project directory for the analysis.

        Args:
            output_dir: Directory for Ghidra output. Uses temp dir if None.

        Returns:
            Path to the Ghidra output directory, or error message
        """
        print(f"{Fore.YELLOW}[*] Running Ghidra headless analysis...{Style.RESET_ALL}")

        if 'ghidra' not in self.available_tools:
            msg = "Ghidra (analyzeHeadless) not found in PATH"
            print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
            return f"Error: {msg}"

        ghidra_path = self.available_tools['ghidra']
        binary = str(self.binary_path)

        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix='bh_ghidra_')

        project_dir = os.path.join(output_dir, 'ghidra_project')
        os.makedirs(project_dir, exist_ok=True)
        project_name = self.binary_path.stem

        cmd = [
            ghidra_path,
            project_dir,
            project_name,
            '-import', binary,
            '-overwrite',
            '-analysisTimeoutPerFile', '300',
        ]

        print(f"{Fore.CYAN}[*] Running: {' '.join(cmd[:4])}...{Style.RESET_ALL}")
        output = self._run_command(cmd, timeout=360)

        if output:
            print(f"{Fore.GREEN}[+] Ghidra analysis complete{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Output: {output_dir}{Style.RESET_ALL}")
            return output_dir
        else:
            return f"Error: Ghidra analysis failed. Check {output_dir} for partial results."

    def disassemble_region(self, address: int, length: int = 100) -> str:
        """
        Disassemble instructions at a specific memory address.

        Args:
            address: Virtual address to start disassembly
            length: Number of instructions to disassemble

        Returns:
            Disassembly output as a string, or error message
        """
        print(f"{Fore.YELLOW}[*] Disassembling at 0x{address:X} ({length} instructions)...{Style.RESET_ALL}")
        binary = str(self.binary_path)

        # Try radare2
        if 'radare2' in self.available_tools:
            r2_path = self.available_tools['radare2']
            output = self._run_command([
                r2_path, '-q', '-c',
                f's {address}; pd {length}',
                binary,
            ])
            if output and output.strip():
                print(f"{Fore.GREEN}[+] Disassembled via radare2{Style.RESET_ALL}")
                return output

        # Try rizin
        if 'rizin' in self.available_tools:
            rz_path = self.available_tools['rizin']
            output = self._run_command([
                rz_path, '-q', '-c',
                f's {address}; pd {length}',
                binary,
            ])
            if output and output.strip():
                print(f"{Fore.GREEN}[+] Disassembled via rizin{Style.RESET_ALL}")
                return output

        return f"Error: Could not disassemble region at 0x{address:X}. No suitable tool available."

    def find_crypto_functions(self) -> List[Dict]:
        """
        Find functions related to cryptographic operations.

        Scans all function names for patterns matching known
        cryptographic function naming conventions.

        Returns:
            List of dicts with keys: name, address, size, category
        """
        print(f"{Fore.YELLOW}[*] Searching for crypto functions...{Style.RESET_ALL}")
        functions = self.list_functions()
        crypto_funcs: List[Dict] = []

        for func in functions:
            if self.CRYPTO_FUNCTION_PATTERNS.search(func['name']):
                func_entry = {**func, 'category': 'crypto'}
                crypto_funcs.append(func_entry)

        print(f"{Fore.GREEN}[+] Found {len(crypto_funcs)} crypto-related functions{Style.RESET_ALL}")
        return crypto_funcs

    def find_auth_functions(self) -> List[Dict]:
        """
        Find functions related to authentication and license verification.

        Scans all function names for patterns matching authentication,
        password handling, session management, and license checking.

        Returns:
            List of dicts with keys: name, address, size, category
        """
        print(f"{Fore.YELLOW}[*] Searching for auth/license functions...{Style.RESET_ALL}")
        functions = self.list_functions()
        auth_funcs: List[Dict] = []

        for func in functions:
            if self.AUTH_FUNCTION_PATTERNS.search(func['name']):
                func_entry = {**func, 'category': 'auth'}
                auth_funcs.append(func_entry)

        print(f"{Fore.GREEN}[+] Found {len(auth_funcs)} auth-related functions{Style.RESET_ALL}")
        return auth_funcs

    def analyze_control_flow(self, function_name: str) -> Dict:
        """
        Perform basic block / control flow graph analysis on a function.

        Uses radare2 or rizin to generate the function's control flow
        graph in ASCII art form.

        Args:
            function_name: Name of the function to analyze

        Returns:
            Dictionary with keys: blocks, edges, graph_text
        """
        print(f"{Fore.YELLOW}[*] Analyzing control flow for: {function_name}{Style.RESET_ALL}")

        if not re.match(r'^[a-zA-Z0-9_.@]+$', function_name):
            return {'blocks': 0, 'edges': 0, 'graph_text': 'Error: Invalid function name'}

        binary = str(self.binary_path)
        result = {'blocks': 0, 'edges': 0, 'graph_text': ''}

        # Try radare2
        if 'radare2' in self.available_tools:
            r2_path = self.available_tools['radare2']
            output = self._run_command([
                r2_path, '-q', '-c',
                f'aaa; agf @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                result['graph_text'] = output
                # Estimate blocks and edges from graph output
                result['blocks'] = output.count('[ ')
                result['edges'] = output.count('---') + output.count('===')
                print(f"{Fore.GREEN}[+] CFG: {result['blocks']} blocks, {result['edges']} edges{Style.RESET_ALL}")
                return result

        # Try rizin
        if 'rizin' in self.available_tools:
            rz_path = self.available_tools['rizin']
            output = self._run_command([
                rz_path, '-q', '-c',
                f'aaa; agf @ sym.{function_name}',
                binary,
            ])
            if output and output.strip():
                result['graph_text'] = output
                result['blocks'] = output.count('[ ')
                result['edges'] = output.count('---') + output.count('===')
                print(f"{Fore.GREEN}[+] CFG: {result['blocks']} blocks, {result['edges']} edges{Style.RESET_ALL}")
                return result

        result['graph_text'] = f'Error: No tool available for CFG analysis of {function_name}'
        print(f"{Fore.YELLOW}[!] CFG analysis requires radare2 or rizin{Style.RESET_ALL}")
        return result

    def full_analysis(self) -> Dict:
        """
        Run all decompiler analyses and return combined results.

        Returns:
            Dictionary containing: functions, crypto_functions,
            auth_functions, tool availability info
        """
        print(f"\n{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Running full decompiler analysis{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")

        functions = self.list_functions()
        crypto_funcs = self.find_crypto_functions()
        auth_funcs = self.find_auth_functions()

        results = {
            'binary': str(self.binary_path),
            'available_tools': list(self.available_tools.keys()),
            'functions_count': len(functions),
            'functions': functions[:200],  # Cap at 200 for sanity
            'crypto_functions': crypto_funcs,
            'auth_functions': auth_funcs,
        }

        print(f"\n{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Decompiler analysis complete{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Functions: {len(functions)} | Crypto: {len(crypto_funcs)} | Auth: {len(auth_funcs)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")

        return results
