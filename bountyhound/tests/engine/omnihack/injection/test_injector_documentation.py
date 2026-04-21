import pytest
import inspect
from engine.omnihack.injection.injector import DLLInjector

def test_manual_techniques_have_clear_documentation():
    """Test that manual injection techniques have clear docstrings"""

    # Check manual_map has documentation
    manual_map_doc = DLLInjector.manual_map.__doc__
    assert manual_map_doc is not None, "manual_map should have docstring"
    assert "not implemented" in manual_map_doc.lower() or "placeholder" in manual_map_doc.lower(), \
        "Should clearly state this is not implemented"
    assert len(manual_map_doc) > 100, "Documentation should be comprehensive"

    # Check thread_hijack has documentation
    thread_hijack_doc = DLLInjector.thread_hijack.__doc__
    assert thread_hijack_doc is not None, "thread_hijack should have docstring"
    assert "not implemented" in thread_hijack_doc.lower() or "placeholder" in thread_hijack_doc.lower(), \
        "Should clearly state this is not implemented"

def test_manual_techniques_raise_not_implemented(monkeypatch):
    """Test that calling manual techniques raises NotImplementedError"""
    # Mock _get_pid to return a fake PID so we don't need a running process
    def mock_get_pid(self):
        return 1234

    monkeypatch.setattr(DLLInjector, '_get_pid', mock_get_pid)
    injector = DLLInjector(process_name="notepad.exe")

    # manual_map should raise NotImplementedError
    with pytest.raises(NotImplementedError, match="(?i)manual"):
        injector.manual_map(dll_path="test.dll")

    # thread_hijack should raise NotImplementedError
    with pytest.raises(NotImplementedError, match="(?i)thread hijacking"):
        injector.thread_hijack(dll_path="test.dll")

def test_manual_techniques_have_references():
    """Test that docstrings include references for implementation"""

    map_doc = DLLInjector.manual_map.__doc__
    hijack_doc = DLLInjector.thread_hijack.__doc__

    # Should have references or resources
    assert "reference" in map_doc.lower() or "resource" in map_doc.lower() or "implement" in map_doc.lower(), \
        "Should provide references for users who want to implement"
    assert "reference" in hijack_doc.lower() or "resource" in hijack_doc.lower() or "implement" in hijack_doc.lower(), \
        "Should provide references for users who want to implement"
