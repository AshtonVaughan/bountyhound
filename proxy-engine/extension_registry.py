"""Extension registry — discover and install extensions from remote registry."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

log = logging.getLogger("proxy-engine.extension-registry")

EXTENSIONS_DIR = Path(__file__).parent / "extensions"
REGISTRY_URL = "https://raw.githubusercontent.com/proxy-engine/extensions/main/registry.json"

_registry_cache: list[dict] = []


async def fetch_registry(registry_url: str | None = None) -> list[dict]:
    """Fetch available extensions from the remote registry."""
    global _registry_cache
    url = registry_url or REGISTRY_URL

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            _registry_cache = resp.json()
            return _registry_cache
    except Exception as e:
        log.warning(f"[registry] Failed to fetch registry: {e}")
        return _registry_cache


async def install_extension(name: str, registry_url: str | None = None) -> dict:
    """Download and install an extension from the registry."""
    if not _registry_cache:
        await fetch_registry(registry_url)

    ext = None
    for item in _registry_cache:
        if item.get("name") == name:
            ext = item
            break

    if not ext:
        return {"error": f"Extension '{name}' not found in registry"}

    download_url = ext.get("download_url", "")
    if not download_url:
        return {"error": f"No download URL for '{name}'"}

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(download_url)
            resp.raise_for_status()

            EXTENSIONS_DIR.mkdir(parents=True, exist_ok=True)
            filename = ext.get("filename", f"{name}.py")
            filepath = EXTENSIONS_DIR / filename
            filepath.write_text(resp.text, encoding="utf-8")

            log.info(f"[registry] Installed extension: {name} -> {filepath}")
            return {
                "installed": name,
                "path": str(filepath),
                "version": ext.get("version", "unknown"),
                "description": ext.get("description", ""),
            }
    except Exception as e:
        return {"error": f"Failed to install '{name}': {e}"}


def list_available() -> list[dict]:
    """List installed and remote extensions."""
    installed = set()
    if EXTENSIONS_DIR.exists():
        for f in EXTENSIONS_DIR.glob("*.py"):
            if not f.name.startswith("_"):
                installed.add(f.stem)

    result = []

    # Installed extensions
    for name in sorted(installed):
        entry = {"name": name, "installed": True, "source": "local"}
        # Check if in registry
        for item in _registry_cache:
            if item.get("name") == name:
                entry.update({
                    "description": item.get("description", ""),
                    "version": item.get("version", ""),
                    "author": item.get("author", ""),
                    "source": "registry",
                })
                break
        result.append(entry)

    # Registry-only extensions
    for item in _registry_cache:
        if item.get("name") not in installed:
            result.append({
                "name": item["name"],
                "installed": False,
                "source": "registry",
                "description": item.get("description", ""),
                "version": item.get("version", ""),
                "author": item.get("author", ""),
            })

    return result
