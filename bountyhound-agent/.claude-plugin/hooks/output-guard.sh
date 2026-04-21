#!/usr/bin/env bash
# output-guard.sh - PostToolUse hook for Bash commands
# Detects when command output exceeds ~80 lines and advises Claude
# to redirect future verbose commands to files.
# Always exits 0 (advisory only, never blocks).

set -euo pipefail

# Read the tool result JSON from stdin
INPUT=$(cat)

# Extract the stdout/output from the tool result
# The hook receives the tool_use_result which contains the output
OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Try different possible shapes of the hook input
    output = data.get('tool_result', {}).get('stdout', '') or data.get('tool_result', {}).get('content', '') or data.get('stdout', '') or data.get('content', '') or ''
    print(output)
except:
    print('')
" 2>/dev/null || echo "")

# Count lines in the output
LINE_COUNT=$(echo "$OUTPUT" | wc -l | tr -d ' ')

if [ "$LINE_COUNT" -gt 80 ]; then
    echo "WARNING: Last command produced ${LINE_COUNT} lines of output."
    echo "To protect context window, redirect verbose output to files:"
    echo "  curl ... > C:/Users/vaugh/Desktop/BountyHound/findings/tmp/response.json"
    echo "  Then read selectively: python3 -c \"import json; print(len(json.load(open('file'))['data']))\""
    echo "  Or use: head -20 file.json"
fi

exit 0
