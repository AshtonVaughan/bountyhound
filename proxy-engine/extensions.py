"""Extensions — plugin system for custom passive and active checks."""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from typing import Callable

from models import ExtensionInfo, Flow, PassiveFinding, ScanFinding

log = logging.getLogger("proxy-engine.extensions")

# Extension directory
EXTENSIONS_DIR = Path(__file__).parent / "extensions"

# Loaded extensions
_extensions: dict[str, dict] = {}  # name -> {info, module, passive_fn, active_fn}


def _load_extension(filepath: Path) -> dict | None:
    """Load a single extension module."""
    try:
        spec = importlib.util.spec_from_file_location(filepath.stem, filepath)
        if not spec or not spec.loader:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        info = ExtensionInfo(
            name=getattr(module, "NAME", filepath.stem),
            description=getattr(module, "DESCRIPTION", ""),
            enabled=getattr(module, "ENABLED", True),
            check_type=getattr(module, "CHECK_TYPE", "passive"),
            file_path=str(filepath),
        )

        return {
            "info": info,
            "module": module,
            "passive_fn": getattr(module, "passive_check", None),
            "active_fn": getattr(module, "active_check", None),
        }
    except Exception as e:
        log.error(f"[extensions] Failed to load {filepath}: {e}")
        return None


def load_all() -> list[ExtensionInfo]:
    """Load all extensions from the extensions directory."""
    _extensions.clear()

    if not EXTENSIONS_DIR.exists():
        EXTENSIONS_DIR.mkdir(parents=True, exist_ok=True)
        # Create example extension
        _create_example()

    for filepath in sorted(EXTENSIONS_DIR.glob("*.py")):
        if filepath.name.startswith("_"):
            continue
        ext = _load_extension(filepath)
        if ext:
            _extensions[ext["info"].name] = ext
            log.info(f"[extensions] Loaded: {ext['info'].name}")

    return [e["info"] for e in _extensions.values()]


def get_extensions() -> list[ExtensionInfo]:
    return [e["info"] for e in _extensions.values()]


def toggle_extension(name: str, enabled: bool) -> bool:
    if name in _extensions:
        _extensions[name]["info"].enabled = enabled
        return True
    return False


def run_passive_checks(flow: Flow) -> list[PassiveFinding]:
    """Run all enabled passive extension checks on a flow."""
    results = []
    for ext in _extensions.values():
        if not ext["info"].enabled or not ext["passive_fn"]:
            continue
        try:
            findings = ext["passive_fn"](flow)
            if findings:
                results.extend(findings)
        except Exception as e:
            log.debug(f"[extensions] Passive check '{ext['info'].name}' error: {e}")
    return results


async def run_active_checks(url: str) -> list[ScanFinding]:
    """Run all enabled active extension checks on a URL."""
    results = []
    for ext in _extensions.values():
        if not ext["info"].enabled or not ext["active_fn"]:
            continue
        try:
            findings = await ext["active_fn"](url)
            if findings:
                results.extend(findings)
        except Exception as e:
            log.debug(f"[extensions] Active check '{ext['info'].name}' error: {e}")
    return results


def _create_example() -> None:
    """Create an example extension file."""
    example = '''"""Example passive scanner extension.

To create a custom check:
1. Create a .py file in the extensions/ directory
2. Define NAME, DESCRIPTION, CHECK_TYPE ("passive" or "active"), ENABLED
3. For passive: define passive_check(flow) -> list[PassiveFinding]
4. For active: define async active_check(url) -> list[ScanFinding]
"""

from models import Flow, PassiveFinding

NAME = "example-check"
DESCRIPTION = "Example: detect debug mode indicators"
CHECK_TYPE = "passive"
ENABLED = True


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Check for debug mode indicators in responses."""
    if not flow.response or not flow.response.body:
        return []

    findings = []
    debug_indicators = [
        "DEBUG = True",
        "DJANGO_DEBUG",
        "debug_toolbar",
        "Xdebug",
        "phpinfo()",
    ]

    body = flow.response.body[:5000]
    for indicator in debug_indicators:
        if indicator.lower() in body.lower():
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="debug-mode-indicator",
                name=f"Debug Mode Indicator: {indicator}",
                severity="medium",
                description=f"Response contains debug indicator: {indicator}",
                evidence=indicator,
                url=flow.request.url,
            ))

    return findings
'''
    example_path = EXTENSIONS_DIR / "example_check.py"
    example_path.write_text(example, encoding="utf-8")
    log.info(f"[extensions] Created example extension at {example_path}")


# ── Rich hooks (Phase 5A) ───────────────────────────────────────────────────

def run_request_hooks(flow: Flow) -> None:
    """Run extension request hooks."""
    for ext in _extensions.values():
        if not ext["info"].enabled:
            continue
        fn = getattr(ext.get("module"), "request_hook", None)
        if fn:
            try:
                fn(flow)
            except Exception as e:
                log.debug(f"[extensions] request_hook '{ext['info'].name}' error: {e}")


def run_response_hooks(flow: Flow) -> None:
    """Run extension response hooks."""
    for ext in _extensions.values():
        if not ext["info"].enabled:
            continue
        fn = getattr(ext.get("module"), "response_hook", None)
        if fn:
            try:
                fn(flow)
            except Exception as e:
                log.debug(f"[extensions] response_hook '{ext['info'].name}' error: {e}")


def run_scanner_hooks(finding: ScanFinding) -> None:
    """Run extension scanner hooks."""
    for ext in _extensions.values():
        if not ext["info"].enabled:
            continue
        fn = getattr(ext.get("module"), "scanner_hook", None)
        if fn:
            try:
                fn(finding)
            except Exception as e:
                log.debug(f"[extensions] scanner_hook '{ext['info'].name}' error: {e}")


def run_intruder_hooks(result) -> None:
    """Run extension intruder hooks."""
    for ext in _extensions.values():
        if not ext["info"].enabled:
            continue
        fn = getattr(ext.get("module"), "intruder_hook", None)
        if fn:
            try:
                fn(result)
            except Exception as e:
                log.debug(f"[extensions] intruder_hook '{ext['info'].name}' error: {e}")


# ── Extension config + state (Phase 5B) ─────────────────────────────────────

def set_extension_config(name: str, config: dict) -> bool:
    """Set configuration for an extension."""
    if name in _extensions:
        _extensions[name]["info"].config = config
        module = _extensions[name].get("module")
        if module and hasattr(module, "configure"):
            try:
                module.configure(config)
            except Exception as e:
                log.debug(f"[extensions] configure '{name}' error: {e}")
        return True
    return False


def get_extension_state(name: str) -> dict:
    """Get state from an extension."""
    if name in _extensions:
        module = _extensions[name].get("module")
        if module and hasattr(module, "get_state"):
            try:
                return module.get_state()
            except Exception:
                pass
        return {"config": _extensions[name]["info"].config}
    return {}


# ── Event bus (Phase 5C) ────────────────────────────────────────────────────

class ExtensionEventBus:
    """Simple pub/sub event bus for extension communication."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list] = {}

    def subscribe(self, event_type: str, callback) -> None:
        self._subscribers.setdefault(event_type, []).append(callback)

    def publish(self, event_type: str, data=None) -> None:
        for cb in self._subscribers.get(event_type, []):
            try:
                cb(data)
            except Exception as e:
                log.debug(f"[event-bus] Error in subscriber for '{event_type}': {e}")

    def unsubscribe(self, event_type: str, callback) -> None:
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb != callback
            ]

event_bus = ExtensionEventBus()


# ── Hot-reload support ────────────────────────────────────────────────────────
_observer = None


def start_hot_reload(extensions_dir: str = "extensions") -> bool:
    """Watch extensions directory for changes and auto-reload."""
    global _observer
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        log.warning("[extensions] watchdog not installed, hot-reload disabled")
        return False

    class ExtensionReloader(FileSystemEventHandler):
        def on_modified(self, event):
            if event.src_path.endswith('.py'):
                log.info(f"[hot-reload] Reloading: {event.src_path}")
                reload_extensions()

        def on_created(self, event):
            if event.src_path.endswith('.py'):
                log.info(f"[hot-reload] New extension: {event.src_path}")
                reload_extensions()

    from pathlib import Path
    ext_path = Path(extensions_dir)
    if not ext_path.exists():
        return False

    _observer = Observer()
    _observer.schedule(ExtensionReloader(), str(ext_path), recursive=False)
    _observer.daemon = True
    _observer.start()
    log.info(f"[hot-reload] Watching {ext_path} for changes")
    return True


def stop_hot_reload():
    """Stop watching extensions directory."""
    global _observer
    if _observer:
        _observer.stop()
        _observer = None


def reload_extensions():
    """Reload all extensions from the extensions directory."""
    load_all()
    log.info(f"[hot-reload] Extensions reloaded: {len(_extensions)} loaded")
