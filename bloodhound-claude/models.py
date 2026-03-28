"""BloodHound-specific Pydantic models for AD enumeration and graph analysis."""

from __future__ import annotations

import sys
import os
import importlib.util
from typing import Any, Optional
from pydantic import BaseModel, Field

# Load bh-core models using absolute import to avoid circular imports
_bh_core_models_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core", "models.py"))
_spec = importlib.util.spec_from_file_location("bh_core_models", _bh_core_models_path)
_bh_core_models = importlib.util.module_from_spec(_spec)
sys.modules["bh_core_models"] = _bh_core_models
_spec.loader.exec_module(_bh_core_models)

BaseJob = _bh_core_models.BaseJob
BaseFinding = _bh_core_models.BaseFinding
BaseRequest = _bh_core_models.BaseRequest


# ── Enumeration request ───────────────────────────────────────────────────────

class BloodHoundCollectRequest(BaseRequest):
    """Request to run SharpHound/BloodHound.py data collection."""
    domain: str                       # Target AD domain (e.g. corp.local)
    dc: str = ""                      # Domain controller IP/hostname
    username: str = ""               # AD username for auth
    password: str = ""               # AD password
    collection_methods: list[str] = Field(
        default_factory=lambda: ["Default"]
    )  # Default, All, DCOnly, Trusts, Session, LoggedOn, ObjectProps, ACL, Container, RDP, DCOM, LocalAdmin
    stealth: bool = False             # Stealth mode — slower but quieter
    use_python_collector: bool = True # Use bloodhound-python vs SharpHound.exe
    nameserver: str = ""             # Custom nameserver for DNS resolution
    dns_tcp: bool = False            # Use TCP for DNS
    timeout: float = 3600.0          # Collection timeout (1h default)
    concurrency: int = 5


class BloodHoundQueryRequest(BaseRequest):
    """Request to run a Cypher query against BloodHound's Neo4j backend."""
    query: str                        # Raw Cypher query
    database_url: str = "bolt://127.0.0.1:7687"
    database_user: str = "neo4j"
    database_password: str = "bloodhound"
    limit: int = 500                  # Result row limit
    timeout: float = 60.0


class BloodHoundPathRequest(BaseRequest):
    """Request to find attack paths in BloodHound data."""
    source: str                       # Source node (SID, name, or label)
    target: str = "Domain Admins"    # Destination node
    path_type: str = "shortest"      # shortest, all, kerberoastable, asreproastable
    database_url: str = "bolt://127.0.0.1:7687"
    database_user: str = "neo4j"
    database_password: str = "bloodhound"
    max_paths: int = 10
    timeout: float = 120.0


# ── Graph / finding models ────────────────────────────────────────────────────

class ADNode(BaseModel):
    """Active Directory node in the BloodHound graph."""
    node_id: str = ""
    node_type: str = ""  # User, Computer, Group, Domain, GPO, OU
    name: str = ""
    object_id: str = ""  # SID or GUID
    properties: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    is_admin_count: bool = False


class ADEdge(BaseModel):
    """Relationship/edge between two AD nodes."""
    source: str = ""
    target: str = ""
    edge_type: str = ""  # MemberOf, AdminTo, HasSession, CanRDP, DCSync, etc.
    properties: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """A complete attack path from source to target."""
    path_id: int = 0
    nodes: list[ADNode] = Field(default_factory=list)
    edges: list[ADEdge] = Field(default_factory=list)
    length: int = 0
    risk_score: float = 0.0
    description: str = ""


class BloodHoundFinding(BaseFinding):
    """BloodHound AD security finding."""
    node_type: str = ""             # Affected node type
    object_id: str = ""             # SID or GUID of affected object
    object_name: str = ""           # Display name
    attack_paths: list[AttackPath] = Field(default_factory=list)
    affected_count: int = 0
    cypher_query: str = ""          # Query that produced this finding
    category: str = ""              # e.g. kerberoastable, asrep, acl_abuse, path_to_da


# ── Job models ────────────────────────────────────────────────────────────────

class BloodHoundCollectJob(BaseJob):
    """BloodHound data collection job."""
    tool: str = "bloodhound"
    job_type: str = "collect"
    domain: str = ""
    dc: str = ""
    collection_methods: list[str] = Field(default_factory=list)
    output_files: list[str] = Field(default_factory=list)  # Paths to JSON zip files
    objects_collected: int = 0
    findings: list[BloodHoundFinding] = Field(default_factory=list)


class BloodHoundQueryJob(BaseJob):
    """BloodHound Cypher query job."""
    tool: str = "bloodhound"
    job_type: str = "query"
    query: str = ""
    rows: list[dict[str, Any]] = Field(default_factory=list)
    row_count: int = 0


class BloodHoundPathJob(BaseJob):
    """BloodHound attack path analysis job."""
    tool: str = "bloodhound"
    job_type: str = "paths"
    source: str = ""
    target: str = ""
    paths: list[AttackPath] = Field(default_factory=list)
    total_paths: int = 0
    findings: list[BloodHoundFinding] = Field(default_factory=list)
