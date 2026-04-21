"""
Tests for Firmware Analyzer Module
Comprehensive tests for firmware analysis and vulnerability detection
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from engine.hardware.firmware.analyzer import FirmwareAnalyzer, FirmwareFinding


@pytest.fixture
def temp_firmware_file():
    """Create temporary firmware file for testing"""
    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
        # Write some test data
        f.write(b'This is a test firmware with password=secret123 and http://example.com\x00\x00\x00')
        f.write(b'\x7fELF\x01\x01\x01\x00' * 10)  # ELF header
        f.write(b'A' * 1000)
        filename = f.name

    yield filename

    # Cleanup
    os.unlink(filename)


class TestFirmwareAnalyzer:
    """Test suite for FirmwareAnalyzer"""

    def test_analyzer_initialization(self, temp_firmware_file):
        """Test analyzer initializes correctly"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        assert analyzer.firmware_path == temp_firmware_file
        assert analyzer.findings == []
        assert analyzer.file_size > 0

    def test_analyzer_nonexistent_file(self):
        """Test analyzer with nonexistent file"""
        analyzer = FirmwareAnalyzer('/nonexistent/file.bin')
        assert analyzer.file_size == 0

    def test_extract_strings(self, temp_firmware_file):
        """Test string extraction from firmware"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        strings = analyzer.extract_strings(min_length=4)

        assert isinstance(strings, list)
        assert len(strings) > 0
        # Should find our test string
        assert any(b'test firmware' in s for s in strings)

    def test_extract_strings_min_length(self, temp_firmware_file):
        """Test string extraction with different min lengths"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)

        short_strings = analyzer.extract_strings(min_length=4)
        long_strings = analyzer.extract_strings(min_length=10)

        assert len(short_strings) >= len(long_strings)

    def test_extract_strings_caching(self, temp_firmware_file):
        """Test string extraction caching"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)

        strings1 = analyzer.extract_strings()
        strings2 = analyzer.extract_strings()

        # Should return cached result
        assert strings1 is strings2

    def test_calculate_entropy(self, temp_firmware_file):
        """Test entropy calculation"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        entropy = analyzer.calculate_entropy()

        assert 0.0 <= entropy <= 8.0
        assert isinstance(entropy, float)

    def test_calculate_entropy_high(self):
        """Test high entropy detection (encrypted/compressed)"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            # Write random-looking data
            f.write(bytes(range(256)) * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        entropy = analyzer.calculate_entropy()

        os.unlink(filename)
        assert entropy > 5.0  # Should have relatively high entropy

    def test_find_credentials_password(self, temp_firmware_file):
        """Test credential detection - passwords"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        findings = analyzer.find_credentials()

        # Should find "password=secret123"
        password_findings = [f for f in findings if 'password' in f.title.lower()]
        assert len(password_findings) > 0

    def test_find_credentials_private_key(self):
        """Test credential detection - private keys"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'-----BEGIN RSA PRIVATE KEY-----\nMIICXAIB...\n')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        findings = analyzer.find_credentials()

        os.unlink(filename)

        # Should find private key
        key_findings = [f for f in findings if 'private' in f.title.lower()]
        assert len(key_findings) > 0

    def test_find_credentials_aws_key(self):
        """Test credential detection - AWS keys"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        findings = analyzer.find_credentials()

        os.unlink(filename)

        # Should find AWS key
        aws_findings = [f for f in findings if 'aws' in f.title.lower()]
        assert len(aws_findings) > 0

    def test_find_urls_http(self, temp_firmware_file):
        """Test URL extraction - HTTP"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        urls = analyzer.find_urls()

        assert 'http' in urls
        # Should find "http://example.com"
        assert len(urls['http']) > 0

    def test_find_urls_ip(self):
        """Test URL extraction - IP addresses"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'Server at 192.168.1.1:8080\n')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        urls = analyzer.find_urls()

        os.unlink(filename)

        assert 'ip_address' in urls
        assert len(urls['ip_address']) > 0

    def test_detect_backdoors_telnetd(self):
        """Test backdoor detection - telnetd"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'Starting telnetd on port 23...\n')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        findings = analyzer.detect_backdoors()

        os.unlink(filename)

        assert len(findings) > 0
        assert any('backdoor' in f.title.lower() for f in findings)

    def test_detect_backdoors_shell(self):
        """Test backdoor detection - shell commands"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'system("/bin/sh")\n')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        findings = analyzer.detect_backdoors()

        os.unlink(filename)

        assert len(findings) > 0

    def test_identify_filesystems_squashfs(self):
        """Test filesystem identification - SquashFS"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'\x00' * 100)
            f.write(b'hsqs')  # SquashFS signature
            f.write(b'\x00' * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        filesystems = analyzer.identify_filesystems()

        os.unlink(filename)

        assert len(filesystems) > 0
        assert any('SquashFS' in fs[1] for fs in filesystems)

    def test_identify_filesystems_gzip(self):
        """Test filesystem identification - GZIP"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'\x1f\x8b')  # GZIP signature
            f.write(b'\x00' * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        filesystems = analyzer.identify_filesystems()

        os.unlink(filename)

        assert len(filesystems) > 0
        assert any('GZIP' in fs[1] for fs in filesystems)

    def test_calculate_hash(self, temp_firmware_file):
        """Test hash calculation"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        hashes = analyzer.calculate_hash()

        assert 'md5' in hashes
        assert 'sha1' in hashes
        assert 'sha256' in hashes
        assert len(hashes['md5']) == 32
        assert len(hashes['sha1']) == 40
        assert len(hashes['sha256']) == 64

    def test_analyze_architecture_elf_32bit(self):
        """Test architecture detection - ELF 32-bit"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'\x7fELF\x01\x01')  # ELF 32-bit LSB
            f.write(b'\x00' * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        arch = analyzer.analyze_architecture()

        os.unlink(filename)

        assert arch is not None
        assert 'ELF 32-bit' in arch

    def test_analyze_architecture_elf_64bit(self):
        """Test architecture detection - ELF 64-bit"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'\x7fELF\x02\x01')  # ELF 64-bit LSB
            f.write(b'\x00' * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        arch = analyzer.analyze_architecture()

        os.unlink(filename)

        assert arch is not None
        assert 'ELF 64-bit' in arch

    def test_analyze_architecture_unknown(self, temp_firmware_file):
        """Test architecture detection - unknown"""
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'UNKNOWN_HEADER')
            f.write(b'\x00' * 100)
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        arch = analyzer.analyze_architecture()

        os.unlink(filename)

        assert arch is None

    @patch('subprocess.run')
    def test_extract_with_binwalk_not_installed(self, mock_run):
        """Test binwalk extraction when not installed"""
        mock_run.return_value.returncode = 1

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'test')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        result = analyzer.extract_with_binwalk()

        os.unlink(filename)

        assert result is False

    @patch('subprocess.run')
    def test_extract_with_binwalk_success(self, mock_run):
        """Test successful binwalk extraction"""
        # Mock version check
        version_result = Mock()
        version_result.returncode = 0

        # Mock extraction
        extract_result = Mock()
        extract_result.returncode = 0
        extract_result.stdout = 'Extraction successful'

        mock_run.side_effect = [version_result, extract_result]

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(b'test')
            filename = f.name

        analyzer = FirmwareAnalyzer(filename)
        result = analyzer.extract_with_binwalk()

        os.unlink(filename)

        assert result is True

    def test_comprehensive_analysis(self, temp_firmware_file):
        """Test comprehensive firmware analysis"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        results = analyzer.comprehensive_analysis()

        assert 'file_info' in results
        assert 'hashes' in results
        assert 'architecture' in results
        assert 'entropy' in results
        assert 'filesystems' in results
        assert 'strings' in results
        assert 'urls' in results
        assert 'credentials' in results
        assert 'backdoors' in results
        assert 'findings' in results

    def test_get_findings_summary_empty(self, temp_firmware_file):
        """Test findings summary when empty"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        summary = analyzer.get_findings_summary()

        assert summary['total'] == 0
        assert summary['critical'] == 0

    def test_get_findings_summary_with_findings(self, temp_firmware_file):
        """Test findings summary with various findings"""
        analyzer = FirmwareAnalyzer(temp_firmware_file)
        analyzer.findings = [
            FirmwareFinding('CRITICAL', 'Test1', 'Desc1', 'Evidence1'),
            FirmwareFinding('HIGH', 'Test2', 'Desc2', 'Evidence2'),
            FirmwareFinding('MEDIUM', 'Test3', 'Desc3', 'Evidence3'),
            FirmwareFinding('INFO', 'Test4', 'Desc4', 'Evidence4'),
        ]

        summary = analyzer.get_findings_summary()
        assert summary['total'] == 4
        assert summary['critical'] == 1
        assert summary['high'] == 1
        assert summary['info'] == 1


class TestFirmwareFinding:
    """Test suite for FirmwareFinding dataclass"""

    def test_firmware_finding_creation(self):
        """Test FirmwareFinding object creation"""
        finding = FirmwareFinding(
            severity='HIGH',
            title='Test Finding',
            description='Test Description',
            evidence='Test Evidence',
            offset=0x1000,
            timestamp=1234567890.0
        )

        assert finding.severity == 'HIGH'
        assert finding.title == 'Test Finding'
        assert finding.offset == 0x1000

    def test_firmware_finding_optional_fields(self):
        """Test FirmwareFinding with optional fields"""
        finding = FirmwareFinding(
            severity='MEDIUM',
            title='Test',
            description='Desc',
            evidence='Evidence'
        )

        assert finding.offset is None
        assert finding.timestamp is None
