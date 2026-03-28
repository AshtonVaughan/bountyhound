"""Audit documentation files for unrealistic coverage claims."""

import re
from pathlib import Path
from typing import List, Tuple


def find_coverage_claims(file_path: Path) -> List[Tuple[int, str]]:
    """Find lines with coverage percentage claims."""
    claims = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            # Look for percentage claims
            if re.search(r'\d+%\s+(coverage|complete|implemented)', line, re.IGNORECASE):
                claims.append((line_num, line.strip()))
            # Look for "100%" specifically
            if '100%' in line:
                claims.append((line_num, line.strip()))
    return claims


def main():
    """Audit all markdown files for coverage claims."""
    import sys
    import io

    # Force UTF-8 output on Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    docs_dir = Path('.')
    md_files = list(docs_dir.glob('*.md')) + list(docs_dir.glob('docs/**/*.md'))

    print("Coverage Claims Audit")
    print("=" * 80)

    for md_file in md_files:
        claims = find_coverage_claims(md_file)
        if claims:
            print(f"\n{md_file}:")
            for line_num, line in claims:
                print(f"  Line {line_num}: {line}")

    print("\n" + "=" * 80)
    print("Review these claims and update to reflect actual implementation status.")


if __name__ == '__main__':
    main()
