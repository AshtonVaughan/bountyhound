"""Test that documentation doesn't contain unrealistic claims."""

import pytest
from pathlib import Path
import re


def test_no_unqualified_100_percent_claims():
    """Test that docs don't claim 100% coverage without caveats."""
    docs = [
        Path("FULL-IMPLEMENTATION-SUMMARY.md"),
        Path("START-HERE.md"),
    ]

    for doc_path in docs:
        if not doc_path.exists():
            continue

        content = doc_path.read_text(encoding='utf-8')

        # Find "100%" claims
        matches = list(re.finditer(r'100%.*?(coverage|complete|asset)', content, re.IGNORECASE))

        for match in matches:
            # Get surrounding context (200 chars before and after)
            context_start = max(0, match.start() - 200)
            context_end = min(len(content), match.end() + 200)
            surrounding = content[context_start:context_end].lower()

            # Check for qualifying language that makes it honest
            honest_qualifiers = [
                'actual', 'measured', 'realistic', 'partial', 'caveat', 'limitation',
                'disclaimer', 'aspirational', 'previous claim', 'stub only',
                'not implemented', 'wrapper', 'external', 'what was built',
                'actual status', 'mostly', 'framework', 'directory structure',
                'original claim', 'unrealistic'
            ]

            has_qualifier = any(q in surrounding for q in honest_qualifiers)

            # Allow "100% COMPLETE" with implementation context
            is_implementation_section = 'implementation complete' in surrounding

            if not (has_qualifier or is_implementation_section):
                # Extract line number for better error message
                line_num = content[:match.start()].count('\n') + 1
                pytest.fail(
                    f"{doc_path}:{line_num}: Unqualified '100%' claim: {match.group()}\n"
                    f"Add qualifying language like 'actual', 'measured', 'limitation', etc."
                )


def test_roi_claims_labeled_as_estimates():
    """Test that ROI projections are clearly labeled as estimates."""
    docs = [
        Path("FULL-IMPLEMENTATION-SUMMARY.md"),
        Path("START-HERE.md"),
        Path("EXPANSION-ROADMAP.md"),
    ]

    for doc_path in docs:
        if not doc_path.exists():
            continue

        content = doc_path.read_text(encoding='utf-8')

        # Find sections with money amounts
        money_pattern = r'\$\d+[KkMm][-\+\/]?\$?\d*[KkMm]?'
        money_matches = list(re.finditer(money_pattern, content))

        if not money_matches:
            continue

        # Check for disclaimers somewhere in the document
        disclaimer_keywords = [
            'estimate', 'potential', 'projected', 'disclaimer', 'may vary',
            'not guaranteed', 'typical', 'conservative', 'optimistic',
            'actual results', 'rough estimate', 'not financial advice',
            'realistic', 'varies', 'depends on', 'unrealistic'
        ]

        has_disclaimer = any(keyword in content.lower() for keyword in disclaimer_keywords)

        if not has_disclaimer:
            pytest.fail(
                f"{doc_path}: Contains ROI/money claims without disclaimer language.\n"
                f"Add disclaimers like 'ESTIMATE', 'may vary', 'not guaranteed', etc."
            )


def test_coverage_percentages_are_realistic():
    """Test that coverage percentages are based on actual measurements."""
    docs = [
        Path("FULL-IMPLEMENTATION-SUMMARY.md"),
    ]

    for doc_path in docs:
        if not doc_path.exists():
            continue

        content = doc_path.read_text(encoding='utf-8')

        # Look for test coverage claims
        coverage_pattern = r'(\d+)%\s+(test\s+)?coverage'
        matches = list(re.finditer(coverage_pattern, content, re.IGNORECASE))

        for match in matches:
            percentage = int(match.group(1))

            # Get surrounding context
            context_start = max(0, match.start() - 150)
            context_end = min(len(content), match.end() + 150)
            surrounding = content[context_start:context_end].lower()

            # If claiming high coverage (>90%), should have "actual" or "measured" nearby
            if percentage > 90:
                has_qualifier = any(q in surrounding for q in ['actual', 'measured', 'pytest', 'tested'])

                if not has_qualifier and 'asset type' not in surrounding:
                    line_num = content[:match.start()].count('\n') + 1
                    pytest.fail(
                        f"{doc_path}:{line_num}: High coverage claim ({percentage}%) lacks evidence.\n"
                        f"Add 'actual', 'measured', or test results to support the claim."
                    )


def test_implementation_status_markers_are_honest():
    """Test that implementation status markers (✅, ⚠️, ❌) are used honestly."""
    doc_path = Path("FULL-IMPLEMENTATION-SUMMARY.md")

    if not doc_path.exists():
        pytest.skip(f"{doc_path} does not exist")

    content = doc_path.read_text(encoding='utf-8')

    # Known stubs should be marked with ❌ or ⚠️, not ✅
    known_stubs = [
        ('hardware', '❌'),
        ('iot', '❌'),
        ('azure', '❌'),
        ('gcp', '❌'),
    ]

    for stub_name, expected_marker in known_stubs:
        # Find sections mentioning this stub
        pattern = rf'.*{stub_name}.*?([✅⚠️❌])'
        matches = re.finditer(pattern, content, re.IGNORECASE)

        for match in matches:
            found_marker = match.group(1)

            # Skip if it's in a limitations section or marked correctly
            context_start = max(0, match.start() - 100)
            context = content[context_start:match.end()].lower()

            if 'limitation' in context or 'stub' in context:
                continue  # Limitations can mention anything

            if found_marker == '✅' and 'not implemented' not in context:
                line_num = content[:match.start()].count('\n') + 1
                pytest.fail(
                    f"{doc_path}:{line_num}: {stub_name} marked as ✅ but is a known stub.\n"
                    f"Should be {expected_marker} or have 'stub'/'not implemented' qualifier."
                )
