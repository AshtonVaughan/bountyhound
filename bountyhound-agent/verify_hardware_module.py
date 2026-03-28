#!/usr/bin/env python3
"""
Hardware/IoT Module Verification Script
Verify all hardware security modules are working correctly
"""

import sys
from colorama import Fore, Style, init

init(autoreset=True)

def verify_imports():
    """Verify all hardware modules can be imported"""
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Verifying Hardware/IoT Module Imports{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")

    modules = [
        ('Serial Scanner', 'engine.hardware.serial_scanner', 'SerialScanner'),
        ('USB Analyzer', 'engine.hardware.usb_analyzer', 'USBAnalyzer'),
        ('Firmware Analyzer', 'engine.hardware.firmware.analyzer', 'FirmwareAnalyzer'),
        ('Bluetooth Scanner', 'engine.hardware.bluetooth_scanner', 'BluetoothScanner'),
        ('JTAG Tester', 'engine.hardware.jtag_tester', 'JTAGTester'),
    ]

    success_count = 0

    for name, module_path, class_name in modules:
        try:
            module = __import__(module_path, fromlist=[class_name])
            cls = getattr(module, class_name)
            print(f"{Fore.GREEN}[+] {name}: {Style.RESET_ALL}Imported successfully")
            print(f"    Module: {module_path}")
            print(f"    Class: {class_name}")
            success_count += 1
        except Exception as e:
            print(f"{Fore.RED}[!] {name}: {Style.RESET_ALL}Import failed")
            print(f"    Error: {e}")

    print(f"\n{Fore.CYAN}[*] Import Success Rate: {success_count}/{len(modules)}{Style.RESET_ALL}")
    return success_count == len(modules)


def verify_instantiation():
    """Verify all hardware modules can be instantiated"""
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Verifying Module Instantiation{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")

    tests = []

    # Serial Scanner
    try:
        from engine.hardware.serial_scanner import SerialScanner
        scanner = SerialScanner(timeout=1.0, rate_limit=0.1)
        assert scanner.timeout == 1.0
        assert scanner.rate_limit == 0.1
        tests.append(('Serial Scanner', True, None))
        print(f"{Fore.GREEN}[+] Serial Scanner: {Style.RESET_ALL}Instantiated successfully")
    except Exception as e:
        tests.append(('Serial Scanner', False, str(e)))
        print(f"{Fore.RED}[!] Serial Scanner: {Style.RESET_ALL}Failed - {e}")

    # USB Analyzer
    try:
        from engine.hardware.usb_analyzer import USBAnalyzer
        analyzer = USBAnalyzer(rate_limit=0.5)
        assert analyzer.rate_limit == 0.5
        tests.append(('USB Analyzer', True, None))
        print(f"{Fore.GREEN}[+] USB Analyzer: {Style.RESET_ALL}Instantiated successfully")
    except Exception as e:
        tests.append(('USB Analyzer', False, str(e)))
        print(f"{Fore.RED}[!] USB Analyzer: {Style.RESET_ALL}Failed - {e}")

    # Firmware Analyzer
    try:
        import tempfile
        from engine.hardware.firmware.analyzer import FirmwareAnalyzer

        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test firmware data')
            temp_path = f.name

        analyzer = FirmwareAnalyzer(temp_path)
        assert analyzer.firmware_path == temp_path
        tests.append(('Firmware Analyzer', True, None))
        print(f"{Fore.GREEN}[+] Firmware Analyzer: {Style.RESET_ALL}Instantiated successfully")

        import os
        os.unlink(temp_path)
    except Exception as e:
        tests.append(('Firmware Analyzer', False, str(e)))
        print(f"{Fore.RED}[!] Firmware Analyzer: {Style.RESET_ALL}Failed - {e}")

    # Bluetooth Scanner
    try:
        from engine.hardware.bluetooth_scanner import BluetoothScanner
        scanner = BluetoothScanner(scan_duration=5.0)
        assert scanner.scan_duration == 5.0
        tests.append(('Bluetooth Scanner', True, None))
        print(f"{Fore.GREEN}[+] Bluetooth Scanner: {Style.RESET_ALL}Instantiated successfully")
    except Exception as e:
        tests.append(('Bluetooth Scanner', False, str(e)))
        print(f"{Fore.RED}[!] Bluetooth Scanner: {Style.RESET_ALL}Failed - {e}")

    # JTAG Tester
    try:
        from engine.hardware.jtag_tester import JTAGTester
        tester = JTAGTester(rate_limit=0.5)
        assert tester.rate_limit == 0.5
        tests.append(('JTAG Tester', True, None))
        print(f"{Fore.GREEN}[+] JTAG Tester: {Style.RESET_ALL}Instantiated successfully")
    except Exception as e:
        tests.append(('JTAG Tester', False, str(e)))
        print(f"{Fore.RED}[!] JTAG Tester: {Style.RESET_ALL}Failed - {e}")

    success_count = sum(1 for _, success, _ in tests if success)
    print(f"\n{Fore.CYAN}[*] Instantiation Success Rate: {success_count}/{len(tests)}{Style.RESET_ALL}")
    return success_count == len(tests)


def count_test_files():
    """Count test files and functions"""
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Test Coverage Statistics{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")

    import os
    import re

    test_dir = 'tests/engine/hardware'
    test_files = []
    total_tests = 0

    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.startswith('test_') and file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    test_count = len(re.findall(r'def test_', content))
                    test_files.append((file, test_count))
                    total_tests += test_count

    print(f"{Fore.CYAN}Test Files:{Style.RESET_ALL}")
    for filename, count in sorted(test_files, key=lambda x: x[1], reverse=True):
        print(f"  {filename}: {count} tests")

    print(f"\n{Fore.GREEN}[+] Total Test Files: {len(test_files)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Total Test Functions: {total_tests}{Style.RESET_ALL}")

    return total_tests


def count_code_lines():
    """Count lines of code in implementation"""
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Implementation Statistics{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")

    import os

    impl_dir = 'engine/hardware'
    total_lines = 0
    files_info = []

    for root, dirs, files in os.walk(impl_dir):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = len(f.readlines())
                    files_info.append((file, lines))
                    total_lines += lines

    print(f"{Fore.CYAN}Implementation Files:{Style.RESET_ALL}")
    for filename, lines in sorted(files_info, key=lambda x: x[1], reverse=True):
        print(f"  {filename}: {lines} lines")

    print(f"\n{Fore.GREEN}[+] Total Implementation Lines: {total_lines:,}{Style.RESET_ALL}")

    return total_lines


def main():
    """Run all verification checks"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Hardware/IoT Security Module - Verification{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    results = []

    # Test imports
    results.append(('Imports', verify_imports()))

    # Test instantiation
    results.append(('Instantiation', verify_instantiation()))

    # Count tests
    test_count = count_test_files()

    # Count code
    code_lines = count_code_lines()

    # Final summary
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Verification Summary{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")

    for name, success in results:
        status = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if success else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        print(f"  {name}: {status}")

    print(f"\n{Fore.CYAN}Module Statistics:{Style.RESET_ALL}")
    print(f"  Implementation: {code_lines:,} lines")
    print(f"  Test Coverage: {test_count} tests")
    print(f"  Modules: 5 (Serial, USB, Firmware, Bluetooth, JTAG)")

    all_passed = all(success for _, success in results)

    if all_passed:
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  [+] ALL CHECKS PASSED - MODULE READY{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.RED}  [!] SOME CHECKS FAILED{Style.RESET_ALL}")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
