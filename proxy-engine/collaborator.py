"""Collaborator — thin wrapper around collaborator_server for backwards compatibility."""

from __future__ import annotations

from collaborator_server import (
    generate_unique_payload,
    get_interactions,
    start_servers,
    stop_servers,
)


async def generate_payload() -> dict:
    """Legacy API — generate a unique OAST payload."""
    payload = generate_unique_payload()
    return payload.model_dump()


async def poll_interactions() -> dict:
    """Legacy API — poll for interactions."""
    interactions = get_interactions()
    return {
        "interactions": [i.model_dump() for i in interactions],
        "count": len(interactions),
    }
