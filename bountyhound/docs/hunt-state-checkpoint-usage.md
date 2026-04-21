# Hunt State Checkpoint System - Usage Guide

**Implemented:** 2026-02-16
**Task:** Task 12 from BountyHound v4.0 Overhaul Plan

## Overview

The Hunt State Checkpoint System enables hunts to save progress and resume after crashes, timeouts, or interruptions. This prevents wasted time re-running already-completed phases.

## How It Works

### Checkpoint Flow

```
Hunt Start
    │
    ├─→ Check for .hunt_state.json
    │   ├─→ Found? Resume from saved phase
    │   └─→ Not found? Start from Phase 0
    │
Phase 0 (Recon) ──────────┐
    │                      │
    └─→ Save checkpoint ───┘
    │
Phase 1 (Discovery) ──────┐
    │                      │
    └─→ Save checkpoint ───┘
    │
Phase 2 (Validation) ─────┐
    │                      │
    └─→ Save checkpoint ───┘
    │
    ... (all phases)
    │
Hunt Complete
    │
    └─→ Delete .hunt_state.json
```

### What's Saved

Each checkpoint contains:
- **target**: Domain being hunted
- **current_phase**: Phase number to resume from
- **completed_phases**: List of successfully completed phases
- **recon_data**: Discovered assets (subdomains, endpoints, etc.)
- **hypotheses**: Generated vulnerability hypotheses
- **findings**: All findings discovered so far
- **timestamp**: When checkpoint was created

## Usage

### Basic Hunt (Auto-Resume)

```python
from engine.agents.phased_hunter import PhasedHunter

# Start a hunt - automatically resumes if checkpoint exists
hunter = PhasedHunter("example.com")
result = hunter.run_full_hunt()
```

### Force Fresh Start

```python
# Disable resume to start from scratch
hunter = PhasedHunter("example.com")
result = hunter.run_full_hunt(resume=False)
```

### Manual Checkpoint Management

```python
from engine.core.hunt_state import HuntState

# Save custom checkpoint
state = HuntState(
    target="example.com",
    current_phase=2,
    completed_phases=[0, 1],
    recon_data={"subdomains": ["api.example.com"]},
    hypotheses=[{"id": "H001", "title": "Test IDOR"}],
    findings=[],
    timestamp=datetime.now().isoformat()
)
state.save("/path/to/hunt_state.json")

# Load checkpoint
state = HuntState.load("/path/to/hunt_state.json")
if state:
    print(f"Resuming from phase {state.current_phase}")
```

## File Location

Checkpoint files are stored in the target's findings directory:

```
C:/Users/vaugh/BountyHound/findings/example.com/.hunt_state.json
```

The `.` prefix hides the file from casual browsing, and it's automatically cleaned up on successful completion.

## Example Scenarios

### Scenario 1: Crash During Validation Phase

```
1. Hunt starts, completes recon (phase 0)
   → Saves checkpoint: phase=1, completed=[0]

2. Hunt runs discovery (phase 1)
   → Saves checkpoint: phase=2, completed=[0,1]

3. Hunt starts validation (phase 2)
   → CRASH! (power outage, network timeout, etc.)

4. Restart hunt:
   hunter = PhasedHunter("example.com")
   result = hunter.run_full_hunt()

   → Loads checkpoint: phase=2
   → Skips phases 0 and 1 (already completed)
   → Resumes from validation phase 2
```

### Scenario 2: Manual Pause/Resume

```python
# Day 1: Start hunt, let it run through recon
hunter = PhasedHunter("example.com")
hunter.run_phase("recon")
# Checkpoint saved automatically

# Day 2: Resume and continue
hunter = PhasedHunter("example.com")
result = hunter.run_full_hunt()  # Resumes from discovery phase
```

## Benefits

1. **No Wasted Time**: Never re-run completed phases
2. **Graceful Failure Handling**: Crashes don't lose all progress
3. **Pause/Resume**: Can stop and continue hunts across sessions
4. **State Preservation**: Recon data, hypotheses, and findings persist
5. **Automatic Cleanup**: Checkpoint deleted on successful completion

## Implementation Details

### Test Coverage

- 7 comprehensive tests in `tests/engine/core/test_hunt_state.py`
- All tests passing
- 90.91% code coverage on `hunt_state.py`
- All 46 existing PhasedHunter tests still pass

### Key Methods

#### `HuntState.save(path: str)`
Saves current hunt state to JSON file with pretty formatting.

#### `HuntState.load(path: str) -> Optional[HuntState]`
Loads hunt state from JSON file. Returns `None` if file doesn't exist or is invalid.

#### `PhasedHunter._save_checkpoint(current_phase: int, state_path: Path)`
Internal method called after each phase to save progress.

### Error Handling

- Invalid JSON files return `None` (graceful degradation)
- Missing checkpoint files start hunt from beginning
- Corrupt checkpoints logged as warnings but don't block hunts

## Future Enhancements

Potential improvements for future versions:

1. **Multi-hunt Checkpoints**: Track multiple concurrent hunts
2. **Cloud Sync**: Sync checkpoints across machines
3. **Checkpoint History**: Keep last N checkpoints for rollback
4. **Compression**: Compress large checkpoint files
5. **Encryption**: Encrypt sensitive checkpoint data

## Related Files

- Implementation: `engine/core/hunt_state.py`
- Tests: `tests/engine/core/test_hunt_state.py`
- Integration: `engine/agents/phased_hunter.py`
- Plan: `docs/plans/2026-02-16-bountyhound-v4-overhaul.md` (Task 12)
