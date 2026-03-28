"""State manager -- loads BaseStateManager from bh-core via importlib to avoid circular import."""

from __future__ import annotations

import sys
import os
import importlib.util

_bh_core_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core"))

# Load bh-core models first (needed by bh-core state)
if "bh_core_models" not in sys.modules:
    _spec = importlib.util.spec_from_file_location("bh_core_models", os.path.join(_bh_core_dir, "models.py"))
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["bh_core_models"] = _mod
    _spec.loader.exec_module(_mod)

_bh_core_models = sys.modules["bh_core_models"]
_saved_models = sys.modules.get("models")
sys.modules["models"] = _bh_core_models

_spec = importlib.util.spec_from_file_location("bh_core_state", os.path.join(_bh_core_dir, "state.py"))
_bh_core_state = importlib.util.module_from_spec(_spec)
sys.modules["bh_core_state"] = _bh_core_state
_spec.loader.exec_module(_bh_core_state)

if _saved_models is not None:
    sys.modules["models"] = _saved_models
elif "models" in sys.modules and sys.modules["models"] is _bh_core_models:
    del sys.modules["models"]

BaseStateManager = _bh_core_state.BaseStateManager

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from models import GobusterJob


class GobusterStateManager(BaseStateManager[GobusterJob]):
    """State manager for Gobuster enumeration jobs."""

    pass  # All functionality inherited from BaseStateManager


