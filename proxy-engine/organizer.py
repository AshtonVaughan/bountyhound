"""Organizer — manual testing notebook: annotate, categorize, link flows to findings."""

from __future__ import annotations

import logging
import time
import uuid

from models import OrganizerItem

log = logging.getLogger("proxy-engine.organizer")

# In-memory storage
items: list[OrganizerItem] = []


def _next_id() -> str:
    return str(uuid.uuid4())[:8]


def create(item: OrganizerItem) -> OrganizerItem:
    """Create a new organizer item."""
    if not item.id:
        item.id = _next_id()
    item.created_at = time.time()
    item.updated_at = time.time()
    items.append(item)
    log.info(f"[organizer] Created item: {item.id} — {item.title}")
    return item


def get(item_id: str) -> OrganizerItem | None:
    """Get an item by ID."""
    for item in items:
        if item.id == item_id:
            return item
    return None


def update(item_id: str, updates: dict) -> OrganizerItem | None:
    """Update an item's fields."""
    item = get(item_id)
    if not item:
        return None

    for key, value in updates.items():
        if hasattr(item, key) and key not in ("id", "created_at"):
            setattr(item, key, value)

    item.updated_at = time.time()
    return item


def delete(item_id: str) -> bool:
    """Delete an item by ID."""
    global items
    before = len(items)
    items = [i for i in items if i.id != item_id]
    return len(items) < before


def list_items(
    category: str | None = None,
    status: str | None = None,
    tag: str | None = None,
) -> list[OrganizerItem]:
    """List items with optional filtering."""
    result = items
    if category:
        result = [i for i in result if i.category == category]
    if status:
        result = [i for i in result if i.status == status]
    if tag:
        result = [i for i in result if tag in i.tags]
    return result


def link_flow(item_id: str, flow_id: str) -> OrganizerItem | None:
    """Link a flow to an organizer item."""
    item = get(item_id)
    if not item:
        return None
    if flow_id not in item.linked_flow_ids:
        item.linked_flow_ids.append(flow_id)
        item.updated_at = time.time()
    return item


def link_finding(item_id: str, finding_id: str) -> OrganizerItem | None:
    """Link a finding to an organizer item."""
    item = get(item_id)
    if not item:
        return None
    if finding_id not in item.linked_finding_ids:
        item.linked_finding_ids.append(finding_id)
        item.updated_at = time.time()
    return item
