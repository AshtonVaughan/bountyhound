"""Project persistence — save/load all state to/from disk (complete)."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from state import state

log = logging.getLogger("proxy-engine.persistence")

PROJECTS_DIR = Path(__file__).parent / "projects"


def _ensure_dir() -> None:
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)


def save_project(name: str | None = None) -> dict:
    """Save all current state to a JSON project file (complete — Task #19)."""
    _ensure_dir()
    if not name:
        name = f"project_{int(time.time())}"
    name = name.replace(" ", "_")
    path = PROJECTS_DIR / f"{name}.json"

    data = {
        "version": 3,
        "name": name,
        "saved_at": time.time(),
        "flows": {},
        "repeater_history": [],
        "ws_messages": [],
        "scope": None,
        "passive_findings": [],
        "match_replace_rules": [],
        "session_rules": [],
        "intruder_jobs": {},
        "scanner_jobs": {},
        "crawl_jobs": {},
        "discovery_jobs": {},
        "sequencer_jobs": {},
        "breakpoint_rules": [],
        "scheduled_scans": [],
    }

    # Flows
    for fid, flow in state.flows.items():
        data["flows"][fid] = flow.model_dump()

    # Repeater history
    for entry in state.repeater_history:
        data["repeater_history"].append(entry.model_dump())

    # WebSocket messages
    for msg in state.ws_messages[-1000:]:
        data["ws_messages"].append(msg.model_dump())

    # Scope config
    try:
        from scope import get_config
        data["scope"] = get_config().model_dump()
    except Exception:
        pass

    # Passive findings
    try:
        import passive_scanner
        data["passive_findings"] = [f.model_dump() for f in passive_scanner.findings[-5000:]]
    except Exception:
        pass

    # Match & Replace rules
    try:
        import match_replace
        data["match_replace_rules"] = [r.model_dump() for r in match_replace.rules]
    except Exception:
        pass

    # Session rules
    try:
        import session_handler
        data["session_rules"] = [r.model_dump() for r in session_handler.rules]
    except Exception:
        pass

    # Intruder jobs (Task #19)
    for jid, job in state.intruder_jobs.items():
        if job.status in ("completed", "cancelled", "error"):
            data["intruder_jobs"][jid] = job.model_dump()

    # Scanner jobs (Task #19)
    for sid, job in state.scanner_jobs.items():
        if job.status in ("completed", "error"):
            data["scanner_jobs"][sid] = job.model_dump()

    # Crawl jobs (Task #19)
    for cid, job in state.crawl_jobs.items():
        if job.status in ("completed", "cancelled"):
            data["crawl_jobs"][cid] = job.model_dump()

    # Discovery jobs (Task #19)
    for did, job in state.discovery_jobs.items():
        if job.status in ("completed", "cancelled"):
            data["discovery_jobs"][did] = job.model_dump()

    # Sequencer jobs (Task #19)
    for sid, job in state.sequencer_jobs.items():
        if job.status in ("completed", "cancelled"):
            data["sequencer_jobs"][sid] = job.model_dump()

    # Breakpoint rules (Task #20)
    data["breakpoint_rules"] = [r.model_dump() for r in state.breakpoint_rules]

    # Scheduled scans (Task #36)
    data["scheduled_scans"] = [s.model_dump() for s in state.scheduled_scans]

    # Collaborator state
    try:
        data["collaborator_interactions"] = [i.model_dump() for i in state.collaborator_interactions]
        data["collaborator_payloads"] = {k: v.model_dump() for k, v in state.collaborator_payloads.items()}
        data["collaborator_config"] = state.collaborator_config.model_dump()
    except Exception:
        pass

    # Scanned endpoints
    try:
        data["scanned_endpoints"] = state.scanned_endpoints
    except Exception:
        pass

    # Resource pools
    try:
        data["resource_pools"] = {k: v.model_dump() for k, v in state.resource_pools.items()}
    except Exception:
        pass

    # TLS client config
    try:
        data["tls_client_config"] = state.tls_client_config.model_dump() if state.tls_client_config else None
    except Exception:
        pass

    # Cookie jar
    try:
        from cookie_jar import jar
        data["cookie_jar"] = jar.get_all()
    except Exception:
        data["cookie_jar"] = []

    # Organizer items
    try:
        import organizer
        data["organizer_items"] = [i.model_dump() for i in organizer.items]
    except Exception:
        data["organizer_items"] = []

    # Macro chains
    try:
        import session_handler
        data["macro_chains"] = [
            c.model_dump() if hasattr(c, 'model_dump') else c
            for c in session_handler.chains
        ]
    except Exception:
        data["macro_chains"] = []

    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    size_kb = path.stat().st_size / 1024
    log.info(f"[persistence] Saved project '{name}' ({size_kb:.1f} KB, {len(data['flows'])} flows)")

    return {
        "name": name,
        "path": str(path),
        "flows": len(data["flows"]),
        "size_kb": round(size_kb, 1),
    }


def load_project(name: str) -> dict:
    """Load state from a project file (complete — Task #19)."""
    _ensure_dir()
    path = PROJECTS_DIR / f"{name}.json"
    if not path.exists():
        path = PROJECTS_DIR / name
    if not path.exists():
        return {"error": f"Project '{name}' not found"}

    data = json.loads(path.read_text(encoding="utf-8"))

    # Clear current state
    state.clear_flows()
    state.repeater_history.clear()
    state.ws_messages.clear()
    state.intruder_jobs.clear()
    state.scanner_jobs.clear()
    state.crawl_jobs.clear()
    state.discovery_jobs.clear()
    state.sequencer_jobs.clear()

    # Restore flows
    from models import Flow
    for fid, flow_data in data.get("flows", {}).items():
        flow = Flow(**flow_data)
        state.flows[flow.id] = flow
    state._flow_counter = max((int(fid) for fid in state.flows.keys()), default=0)

    # Restore repeater history
    from models import RepeaterHistoryEntry
    for entry_data in data.get("repeater_history", []):
        state.repeater_history.append(RepeaterHistoryEntry(**entry_data))
    if state.repeater_history:
        state._repeater_counter = max(e.id for e in state.repeater_history)

    # Restore WS messages
    from models import WebSocketMessage
    for msg_data in data.get("ws_messages", []):
        state.ws_messages.append(WebSocketMessage(**msg_data))

    # Restore scope
    if data.get("scope"):
        try:
            from scope import set_config
            from models import ScopeConfig
            set_config(ScopeConfig(**data["scope"]))
        except Exception:
            pass

    # Restore passive findings
    if data.get("passive_findings"):
        try:
            import passive_scanner
            from models import PassiveFinding
            passive_scanner.findings.clear()
            for f_data in data["passive_findings"]:
                passive_scanner.findings.append(PassiveFinding(**f_data))
        except Exception:
            pass

    # Restore match & replace rules
    if data.get("match_replace_rules"):
        try:
            import match_replace
            from models import MatchReplaceRule
            match_replace.rules.clear()
            for r_data in data["match_replace_rules"]:
                match_replace.rules.append(MatchReplaceRule(**r_data))
        except Exception:
            pass

    # Restore session rules
    if data.get("session_rules"):
        try:
            import session_handler
            from models import SessionRule
            session_handler.rules.clear()
            for r_data in data["session_rules"]:
                session_handler.rules.append(SessionRule(**r_data))
        except Exception:
            pass

    # Restore intruder jobs (Task #19)
    from models import IntruderJob
    for jid, job_data in data.get("intruder_jobs", {}).items():
        state.intruder_jobs[jid] = IntruderJob(**job_data)

    # Restore scanner jobs (Task #19)
    from models import ScanJob
    for sid, job_data in data.get("scanner_jobs", {}).items():
        state.scanner_jobs[sid] = ScanJob(**job_data)

    # Restore crawl jobs (Task #19)
    from models import CrawlJob
    for cid, job_data in data.get("crawl_jobs", {}).items():
        state.crawl_jobs[cid] = CrawlJob(**job_data)

    # Restore discovery jobs (Task #19)
    from models import DiscoveryJob
    for did, job_data in data.get("discovery_jobs", {}).items():
        state.discovery_jobs[did] = DiscoveryJob(**job_data)

    # Restore sequencer jobs (Task #19)
    from models import SequencerResult
    for sid, job_data in data.get("sequencer_jobs", {}).items():
        state.sequencer_jobs[sid] = SequencerResult(**job_data)

    # Restore breakpoint rules (Task #20)
    from models import BreakpointRule
    state.breakpoint_rules = [BreakpointRule(**r) for r in data.get("breakpoint_rules", [])]

    # Restore scheduled scans (Task #36)
    from models import ScheduledScan
    state.scheduled_scans = [ScheduledScan(**s) for s in data.get("scheduled_scans", [])]

    # Restore collaborator state
    from models import CollaboratorInteraction, CollaboratorPayload, CollaboratorConfig, ResourcePool, TLSClientConfig

    if "collaborator_interactions" in data:
        state.collaborator_interactions = [CollaboratorInteraction(**i) for i in data["collaborator_interactions"]]
    if "collaborator_payloads" in data:
        state.collaborator_payloads = {k: CollaboratorPayload(**v) for k, v in data["collaborator_payloads"].items()}
    if "collaborator_config" in data:
        state.collaborator_config = CollaboratorConfig(**data["collaborator_config"])
    if "scanned_endpoints" in data:
        state.scanned_endpoints = data["scanned_endpoints"]
    if "resource_pools" in data:
        state.resource_pools = {k: ResourcePool(**v) for k, v in data["resource_pools"].items()}
    if "tls_client_config" in data and data["tls_client_config"]:
        state.tls_client_config = TLSClientConfig(**data["tls_client_config"])

    # Restore cookie jar
    if data.get("cookie_jar"):
        try:
            from cookie_jar import jar
            jar.clear()
            for cookie in data["cookie_jar"]:
                jar.set_cookie(
                    domain=cookie.get("domain", ""),
                    name=cookie.get("name", ""),
                    value=cookie.get("value", ""),
                    path=cookie.get("path", "/"),
                    secure=cookie.get("secure", False),
                    httponly=cookie.get("httponly", False),
                    expires=cookie.get("expires"),
                )
        except Exception:
            pass

    # Restore organizer items
    if data.get("organizer_items"):
        try:
            import organizer
            from models import OrganizerItem
            organizer.items.clear()
            for item_data in data["organizer_items"]:
                organizer.items.append(OrganizerItem(**item_data))
        except Exception:
            pass

    # Restore macro chains
    if data.get("macro_chains"):
        try:
            import session_handler
            from models import MacroChain
            session_handler.chains.clear()
            for chain_data in data["macro_chains"]:
                session_handler.chains.append(MacroChain(**chain_data))
        except Exception:
            pass

    log.info(f"[persistence] Loaded project '{name}' ({len(state.flows)} flows)")
    return {
        "name": name,
        "flows_loaded": len(state.flows),
        "repeater_entries": len(state.repeater_history),
        "intruder_jobs": len(state.intruder_jobs),
        "scanner_jobs": len(state.scanner_jobs),
    }


def list_projects() -> list[dict]:
    """List all saved projects."""
    _ensure_dir()
    projects = []
    for path in sorted(PROJECTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            projects.append({
                "name": data.get("name", path.stem),
                "saved_at": data.get("saved_at", 0),
                "flows": len(data.get("flows", {})),
                "size_kb": round(path.stat().st_size / 1024, 1),
            })
        except Exception:
            pass
    return projects


def delete_project(name: str) -> bool:
    """Delete a saved project."""
    _ensure_dir()
    path = PROJECTS_DIR / f"{name}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def auto_save() -> dict | None:
    """Auto-save current state if there are flows."""
    if len(state.flows) == 0:
        return None
    return save_project("autosave")
