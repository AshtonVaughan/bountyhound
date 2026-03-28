"""
Tests for HuntState checkpoint system.

Verifies that hunts can be saved, loaded, and resumed after failures.
"""

import json
import pytest
from pathlib import Path
from datetime import datetime

from engine.core.hunt_state import HuntState


class TestHuntState:
    """Test hunt state checkpoint functionality."""

    def test_save_and_load(self, tmp_path):
        """Save and load hunt state successfully."""
        state_path = tmp_path / "hunt_state.json"

        # Create and save state
        state = HuntState(
            target="example.com",
            current_phase=2,
            completed_phases=[0, 1],
            recon_data={"subdomains": ["api.example.com", "www.example.com"]},
            hypotheses=[
                {"id": "H001", "title": "Test IDOR"},
                {"id": "H002", "title": "Test XSS"}
            ],
            findings=[],
            timestamp=datetime.now().isoformat()
        )

        state.save(str(state_path))

        # Verify file exists
        assert state_path.exists()

        # Load state
        loaded = HuntState.load(str(state_path))

        # Verify loaded state matches original
        assert loaded.target == "example.com"
        assert loaded.current_phase == 2
        assert loaded.completed_phases == [0, 1]
        assert loaded.recon_data == {"subdomains": ["api.example.com", "www.example.com"]}
        assert len(loaded.hypotheses) == 2
        assert loaded.hypotheses[0]["id"] == "H001"

    def test_load_nonexistent_file_returns_none(self, tmp_path):
        """Loading non-existent state file returns None."""
        state_path = tmp_path / "nonexistent.json"
        loaded = HuntState.load(str(state_path))
        assert loaded is None

    def test_state_persistence_across_crashes(self, tmp_path):
        """State can be resumed after a simulated crash."""
        state_path = tmp_path / "hunt_state.json"

        # Create initial state (before crash)
        state1 = HuntState(
            target="vulnerable.com",
            current_phase=1,
            completed_phases=[0],
            recon_data={"endpoints": ["/api/v1/users"]},
            timestamp=datetime.now().isoformat()
        )
        state1.save(str(state_path))

        # Simulate crash - load state and continue
        state2 = HuntState.load(str(state_path))
        assert state2 is not None
        assert state2.target == "vulnerable.com"
        assert state2.current_phase == 1
        assert state2.completed_phases == [0]

        # Update state (phase 1 completed, moving to phase 2)
        state2.current_phase = 2
        state2.completed_phases.append(1)
        state2.hypotheses = [{"id": "H001", "title": "GraphQL IDOR"}]
        state2.save(str(state_path))

        # Simulate another crash - load again
        state3 = HuntState.load(str(state_path))
        assert state3.current_phase == 2
        assert state3.completed_phases == [0, 1]
        assert len(state3.hypotheses) == 1

    def test_resume_from_specific_phase(self, tmp_path):
        """Can resume hunt from a specific phase checkpoint."""
        state_path = tmp_path / "hunt_state.json"

        # Hunt completes phases 0, 1, 2 then crashes
        state = HuntState(
            target="example.com",
            current_phase=3,
            completed_phases=[0, 1, 2],
            recon_data={"subdomains": ["api.example.com"]},
            hypotheses=[{"id": "H001", "title": "Test"}],
            findings=[
                {"title": "IDOR found", "severity": "HIGH"},
                {"title": "XSS found", "severity": "MEDIUM"}
            ],
            timestamp=datetime.now().isoformat()
        )
        state.save(str(state_path))

        # Resume from checkpoint
        loaded = HuntState.load(str(state_path))
        assert loaded.current_phase == 3  # Should resume from phase 3
        assert loaded.completed_phases == [0, 1, 2]
        assert len(loaded.findings) == 2  # Previous findings preserved

    def test_state_includes_all_required_fields(self, tmp_path):
        """State file contains all required fields."""
        state_path = tmp_path / "hunt_state.json"

        state = HuntState(
            target="test.com",
            current_phase=0,
            completed_phases=[],
            timestamp=datetime.now().isoformat()
        )
        state.save(str(state_path))

        # Read raw JSON
        with open(state_path, 'r') as f:
            data = json.load(f)

        # Verify required fields
        assert "target" in data
        assert "current_phase" in data
        assert "completed_phases" in data
        assert "timestamp" in data

    def test_save_with_empty_findings(self, tmp_path):
        """Can save state with no findings yet."""
        state_path = tmp_path / "hunt_state.json"

        state = HuntState(
            target="example.com",
            current_phase=0,
            completed_phases=[],
            recon_data=None,
            hypotheses=None,
            findings=None,
            timestamp=datetime.now().isoformat()
        )
        state.save(str(state_path))

        loaded = HuntState.load(str(state_path))
        assert loaded.recon_data is None
        assert loaded.hypotheses is None
        assert loaded.findings is None

    def test_state_update_preserves_previous_data(self, tmp_path):
        """Updating state preserves previous phase data."""
        state_path = tmp_path / "hunt_state.json"

        # Initial state
        state = HuntState(
            target="example.com",
            current_phase=1,
            completed_phases=[0],
            recon_data={"subdomains": ["api.example.com"]},
            timestamp=datetime.now().isoformat()
        )
        state.save(str(state_path))

        # Load and update
        state = HuntState.load(str(state_path))
        state.current_phase = 2
        state.completed_phases.append(1)
        state.hypotheses = [{"id": "H001"}]
        state.save(str(state_path))

        # Verify recon_data still exists
        state = HuntState.load(str(state_path))
        assert state.recon_data == {"subdomains": ["api.example.com"]}
        assert state.hypotheses == [{"id": "H001"}]
