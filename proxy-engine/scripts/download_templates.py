"""Download nuclei-templates repository for native scanner."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

TEMPLATES_DIR = Path(__file__).parent.parent / "nuclei-templates"
REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
ZIP_URL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"


def download_via_git() -> bool:
    """Clone templates repo via git (preferred — shallow clone)."""
    if shutil.which("git") is None:
        return False

    if TEMPLATES_DIR.exists():
        print(f"[*] Templates directory exists, pulling latest...")
        result = subprocess.run(
            ["git", "-C", str(TEMPLATES_DIR), "pull", "--depth=1"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"[+] Updated templates: {TEMPLATES_DIR}")
            return True
        # If pull fails, remove and re-clone
        shutil.rmtree(TEMPLATES_DIR, ignore_errors=True)

    print(f"[*] Cloning nuclei-templates (shallow)...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", REPO_URL, str(TEMPLATES_DIR)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"[+] Cloned templates to: {TEMPLATES_DIR}")
        return True

    print(f"[-] Git clone failed: {result.stderr}")
    return False


def download_via_zip() -> bool:
    """Download templates as zip (fallback)."""
    zip_path = TEMPLATES_DIR.parent / "nuclei-templates.zip"

    print(f"[*] Downloading templates zip...")
    try:
        urlretrieve(ZIP_URL, str(zip_path))
    except Exception as e:
        print(f"[-] Download failed: {e}")
        return False

    print(f"[*] Extracting...")
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(TEMPLATES_DIR.parent)

        # Rename extracted directory
        extracted = TEMPLATES_DIR.parent / "nuclei-templates-main"
        if extracted.exists():
            if TEMPLATES_DIR.exists():
                shutil.rmtree(TEMPLATES_DIR)
            extracted.rename(TEMPLATES_DIR)

        zip_path.unlink(missing_ok=True)
        print(f"[+] Extracted templates to: {TEMPLATES_DIR}")
        return True
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        return False


def build_index() -> int:
    """Build template index after download."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from nuclei_runtime import NucleiRuntime

    runtime = NucleiRuntime.get_instance()
    count = runtime.reload_index()
    print(f"[+] Indexed {count} templates")
    return count


def main() -> None:
    print("=" * 60)
    print("Nuclei Templates Downloader")
    print("=" * 60)

    if not download_via_git():
        if not download_via_zip():
            print("[-] Failed to download templates via git or zip")
            sys.exit(1)

    # Count templates
    yaml_count = len(list(TEMPLATES_DIR.rglob("*.yaml"))) + len(list(TEMPLATES_DIR.rglob("*.yml")))
    print(f"[*] Found {yaml_count} YAML template files")

    # Build index
    count = build_index()
    print(f"\n[+] Done! {count} templates ready for native scanning.")


if __name__ == "__main__":
    main()
