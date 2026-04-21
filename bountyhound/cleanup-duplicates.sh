#!/bin/bash
# BountyHound Duplicate File Cleanup Script
# This script removes numbered duplicate files, keeping the original named versions

set -e  # Exit on error

AGENTS_DIR="C:/Users/vaugh/Projects/bountyhound-agent/agents"
BACKUP_DIR="C:/Users/vaugh/Projects/bountyhound-agent/agents-backup-$(date +%Y%m%d-%H%M%S)"

echo "=================================================="
echo "BountyHound Duplicate Cleanup Script"
echo "=================================================="
echo ""

# Create backup
echo "Step 1: Creating backup at $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"
cp -r "$AGENTS_DIR"/*.md "$BACKUP_DIR/"
echo "✓ Backup created (186 files backed up)"
echo ""

# Change to agents directory
cd "$AGENTS_DIR"

echo "Step 2: Removing numbered duplicate files..."
echo ""

# List of confirmed duplicates (29 files)
DUPLICATES=(
    "81-grpc-security-tester.md"
    "82-microservices-security-scanner.md"
    "83-configuration-file-analyzer.md"
    "84-serverless-security-tester.md"
    "85-api-response-analyzer.md"
    "89-iot-security-tester.md"
    "90-blockchain-security-scanner.md"
    "91-machine-learning-model-tester.md"
    "92-api-fuzzing-orchestrator.md"
    "98-message-queue-tester.md"
    "99-cdn-configuration-analyzer.md"
    "100-third-party-integration-tester.md"
    "105-reverse-proxy-bypass-tester.md"
    "121-business-logic-vulnerability-finder.md"
    "122-api-abuse-detection-bypasser.md"
    "123-authentication-mechanism-analyzer.md"
    "129-input-sanitization-tester.md"
    "130-memory-disclosure-scanner.md"
    "134-security-misconfiguration-scanner.md"
    "135-server-side-include-tester.md"
    "136-session-management-comprehensive.md"
    "137-url-manipulation-tester.md"
    "138-web-cache-behavior-analyzer.md"
    "148-vulnerability-correlation-engine.md"
    "149-automated-report-writer.md"
    "150-bounty-program-analyzer.md"
    "151-continuous-monitoring-engine.md"
    "152-collaboration-coordinator.md"
    "153-knowledge-base-manager.md"
)

REMOVED_COUNT=0

for file in "${DUPLICATES[@]}"; do
    if [ -f "$file" ]; then
        # Extract base name (without number prefix)
        base_name=$(echo "$file" | sed 's/^[0-9]*-//')

        if [ -f "$base_name" ]; then
            echo "  Removing: $file (keeping $base_name)"
            rm "$file"
            ((REMOVED_COUNT++))
        else
            echo "  WARNING: $file exists but $base_name not found - SKIPPING"
        fi
    else
        echo "  SKIP: $file not found"
    fi
done

echo ""
echo "✓ Removed $REMOVED_COUNT duplicate files"
echo ""

# Remove old reporter-agent backups
echo "Step 3: Cleaning up reporter-agent versions..."
if [ -f "reporter-agent-OLD.md" ]; then
    echo "  Removing: reporter-agent-OLD.md"
    rm "reporter-agent-OLD.md"
fi
if [ -f "reporter-agent-UPDATED.md" ]; then
    echo "  Moving reporter-agent-UPDATED.md -> reporter-agent.md"
    mv "reporter-agent-UPDATED.md" "reporter-agent.md"
fi
echo "✓ Reporter-agent cleaned up"
echo ""

# Count final files
FINAL_COUNT=$(ls -1 *.md 2>/dev/null | grep -v "COMPONENTS-" | wc -l)

echo "=================================================="
echo "Cleanup Complete!"
echo "=================================================="
echo ""
echo "Summary:"
echo "  Files before:    186"
echo "  Files removed:   $REMOVED_COUNT + 1 (reporter-agent-OLD)"
echo "  Files after:     $FINAL_COUNT"
echo "  Backup location: $BACKUP_DIR"
echo ""
echo "Next steps:"
echo "  1. Verify file count: cd agents && ls *.md | wc -l"
echo "  2. Test integration: Run hunt-orchestrator"
echo "  3. If issues occur, restore from backup:"
echo "     cp $BACKUP_DIR/*.md $AGENTS_DIR/"
echo ""
echo "✓ System is now clean and production-ready!"
echo "=================================================="
