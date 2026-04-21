import os
import re
import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BANNED_PATHS = [
    r'~/bounty-findings/',
    r'\$HOME/bounty-findings/',
    r'~/bounty-findings',
]

def get_all_files(extensions=('.md', '.py')):
    """Get all markdown and python files in the repo."""
    files = []
    # Exclude documentation and plan files that document old behavior
    excluded_files = [
        'AUTH_MANAGER_IMPLEMENTATION.md',
        'COMPREHENSIVE-CODEBASE-ANALYSIS.md',
        'MISSING-COMPONENTS.md',
        'PIPELINE-V2-CHANGELOG.md',
        'SYSTEM-FLOWCHART.md',
        'test_path_consistency.py',  # Don't test the test file itself
    ]
    excluded_dirs = ['plans']  # Exclude docs/plans directory
    excluded_paths = [
        'docs\\COMPLETE-DATABASE-EXPORT.md',
        'docs/COMPLETE-DATABASE-EXPORT.md',
    ]

    for root, dirs, filenames in os.walk(REPO_ROOT):
        # Remove excluded directories from traversal
        dirs[:] = [d for d in dirs if d not in ('node_modules', '__pycache__', '.git', 'disabled') and d not in excluded_dirs]
        for f in filenames:
            if any(f.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, f)
                # Skip excluded files
                if f in excluded_files:
                    continue
                # Skip excluded paths
                if any(excl in filepath for excl in excluded_paths):
                    continue
                files.append(filepath)
    return files

def test_no_banned_paths():
    """No file should reference the old ~/bounty-findings/ path."""
    violations = []
    for filepath in get_all_files():
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        for pattern in BANNED_PATHS:
            if pattern in content:
                violations.append(f"{filepath}: contains '{pattern}'")
    assert violations == [], f"Found banned path references:\n" + "\n".join(violations)
