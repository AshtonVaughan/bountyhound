import pytest
from unittest.mock import Mock, patch
from engine.omnihack.game_hacker import GameHacker

@pytest.fixture
def hacker():
    return GameHacker()

def test_attach_to_process(hacker):
    """Test process attachment"""
    with patch('psutil.process_iter') as mock_iter:
        mock_process = Mock()
        mock_process.info = {'pid': 1234, 'name': 'game.exe'}
        mock_iter.return_value = [mock_process]

        result = hacker.attach_to_process("game.exe")

        assert result is not None

def test_scan_memory_patterns(hacker):
    """Test memory pattern scanning"""
    with patch.object(hacker, 'process') as mock_process:
        mock_process.pid = 1234

        patterns = ["48 65 6C 6C 6F"]  # "Hello" in hex
        results = hacker.scan_memory_patterns(patterns)

        assert isinstance(results, list)

def test_test_anti_cheat_bypass(hacker):
    """Test anti-cheat detection"""
    with patch('psutil.process_iter') as mock_iter:
        mock_process = Mock()
        mock_process.info = {'name': 'EasyAntiCheat.exe'}
        mock_iter.return_value = [mock_process]

        result = hacker.test_anti_cheat_bypass("game.exe")

        assert isinstance(result, dict)
        assert 'detected' in result
        assert 'anti_cheats' in result

def test_monitor_network_traffic(hacker):
    """Test network traffic monitoring"""
    with patch.object(hacker, 'process') as mock_process:
        mock_process.pid = 1234

        packets = hacker.monitor_network_traffic("game.exe", duration=1)

        assert isinstance(packets, list)
