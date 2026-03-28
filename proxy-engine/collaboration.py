"""Real-Time Collaboration — WebSocket-based state sync between testers.

Features: shared flow view, finding annotations, scope changes broadcast.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger("proxy-engine.collab")

# Connected clients
_clients: dict[str, WebSocket] = {}
_client_info: dict[str, dict] = {}


async def websocket_handler(websocket: WebSocket) -> None:
    """Handle a collaboration WebSocket connection."""
    await websocket.accept()
    client_id = f"client-{int(time.time() * 1000)}-{len(_clients)}"

    try:
        # Wait for identification message
        init = await asyncio.wait_for(websocket.receive_json(), timeout=10)
        name = init.get("name", f"Tester-{len(_clients) + 1}")
        client_id = init.get("client_id", client_id)
    except Exception:
        name = f"Tester-{len(_clients) + 1}"

    _clients[client_id] = websocket
    _client_info[client_id] = {
        "name": name,
        "connected_at": time.time(),
        "last_activity": time.time(),
    }

    log.info(f"[collab] Client connected: {name} ({client_id})")

    # Notify others
    await _broadcast({
        "type": "client_joined",
        "client_id": client_id,
        "name": name,
        "clients": list(_client_info.values()),
    }, exclude=client_id)

    # Send current state to new client
    await websocket.send_json({
        "type": "init",
        "client_id": client_id,
        "clients": [{"id": cid, **info} for cid, info in _client_info.items()],
    })

    try:
        while True:
            data = await websocket.receive_json()
            _client_info[client_id]["last_activity"] = time.time()
            await _handle_message(client_id, data)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.debug(f"[collab] Client error: {e}")
    finally:
        _clients.pop(client_id, None)
        _client_info.pop(client_id, None)
        log.info(f"[collab] Client disconnected: {name}")
        await _broadcast({
            "type": "client_left",
            "client_id": client_id,
            "name": name,
            "clients": list(_client_info.values()),
        })


async def _handle_message(client_id: str, data: dict) -> None:
    """Handle an incoming collaboration message."""
    msg_type = data.get("type", "")

    if msg_type == "annotation":
        # Finding/flow annotation
        await _broadcast({
            "type": "annotation",
            "client_id": client_id,
            "name": _client_info.get(client_id, {}).get("name", "Unknown"),
            "target_type": data.get("target_type", ""),  # "flow" or "finding"
            "target_id": data.get("target_id", ""),
            "text": data.get("text", ""),
            "timestamp": time.time(),
        }, exclude=client_id)

    elif msg_type == "scope_change":
        await _broadcast({
            "type": "scope_change",
            "client_id": client_id,
            "name": _client_info.get(client_id, {}).get("name", "Unknown"),
            "action": data.get("action", ""),
            "rule": data.get("rule", {}),
            "timestamp": time.time(),
        }, exclude=client_id)

    elif msg_type == "finding_shared":
        await _broadcast({
            "type": "finding_shared",
            "client_id": client_id,
            "name": _client_info.get(client_id, {}).get("name", "Unknown"),
            "finding": data.get("finding", {}),
            "message": data.get("message", ""),
            "timestamp": time.time(),
        }, exclude=client_id)

    elif msg_type == "cursor":
        # Share what the user is looking at
        await _broadcast({
            "type": "cursor",
            "client_id": client_id,
            "name": _client_info.get(client_id, {}).get("name", "Unknown"),
            "panel": data.get("panel", ""),
            "flow_id": data.get("flow_id", ""),
        }, exclude=client_id)

    elif msg_type == "chat":
        await _broadcast({
            "type": "chat",
            "client_id": client_id,
            "name": _client_info.get(client_id, {}).get("name", "Unknown"),
            "message": data.get("message", ""),
            "timestamp": time.time(),
        }, exclude=client_id)


async def _broadcast(data: dict, exclude: str | None = None) -> None:
    """Send a message to all connected clients, optionally excluding one."""
    disconnected = []
    for cid, ws in _clients.items():
        if cid == exclude:
            continue
        try:
            await ws.send_json(data)
        except Exception:
            disconnected.append(cid)

    for cid in disconnected:
        _clients.pop(cid, None)
        _client_info.pop(cid, None)


def get_connected_clients() -> list[dict]:
    """Get info about connected clients."""
    return [{"id": cid, **info} for cid, info in _client_info.items()]


def get_client_count() -> int:
    return len(_clients)


async def broadcast_event(event_type: str, data: Any) -> None:
    """Broadcast an event from the server to all clients."""
    await _broadcast({
        "type": event_type,
        "data": data,
        "timestamp": time.time(),
        "source": "server",
    })
