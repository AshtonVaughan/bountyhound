
from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze

"""Discovery Engine - LLM-Powered Vulnerability Hypothesis Generator"""
import json
import re
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

@dataclass
class Hypothesis:
    id: str
    hypothesis: str
    category: str
    confidence: str
    reasoning: str
    test_method: str
    payload: str
    success_indicator: str
    track: str
    priority_score: float = 0.0
    tech_stack: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
