"""mitmproxy addon — captures flows, supports intercept, match/replace, scope, WebSocket, passive scanning."""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

from mitmproxy import http, websocket

from models import Flow, FlowRequest, FlowResponse, WebSocketMessage
from state import state

log = logging.getLogger("proxy-engine.addon")


def _headers_to_dict(headers) -> dict[str, str]:
    result: dict[str, str] = {}
    for k, v in headers.fields:
        result[k.decode("utf-8", errors="replace")] = v.decode("utf-8", errors="replace")
    return result


def _body_to_str(content: bytes | None) -> str | None:
    if content is None:
        return None
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return f"<binary {len(content)} bytes>"


class ProxyAddon:
    """mitmproxy addon: capture, intercept, match/replace, scope, WebSocket, passive scan."""

    async def request(self, flow: http.HTTPFlow) -> None:
        from scope import is_in_scope

        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or ""

        # TLS pass-through check
        try:
            from tls_passthrough import should_passthrough
            if should_passthrough(host):
                return
        except ImportError:
            pass

        # Scope check — if not in scope, let it pass through unrecorded
        if not is_in_scope(host, flow.request.pretty_url):
            return

        # Apply match & replace rules (request phase) — now scope-aware
        try:
            import match_replace
            if match_replace.rules:
                method = flow.request.method
                url = flow.request.pretty_url
                headers = _headers_to_dict(flow.request.headers)
                body = _body_to_str(flow.request.content)

                method, url, headers, body = match_replace.apply_request_rules(
                    method, url, headers, body, host=host,
                )

                flow.request.method = method
                flow.request.url = url
                for k, v in headers.items():
                    flow.request.headers[k] = v
                if body is not None:
                    flow.request.content = body.encode("utf-8")
        except Exception as e:
            log.debug(f"[match_replace] Request rule error: {e}")

        # Cookie jar integration — inject stored cookies
        try:
            from cookie_jar import jar
            req_headers = _headers_to_dict(flow.request.headers)
            merged = jar.inject_cookies(flow.request.pretty_url, req_headers)
            if "Cookie" in merged and merged.get("Cookie") != req_headers.get("Cookie", req_headers.get("cookie", "")):
                flow.request.headers["Cookie"] = merged["Cookie"]
        except Exception:
            pass

        flow_id = state.next_flow_id()
        flow.metadata["proxy_engine_id"] = flow_id

        req = FlowRequest(
            method=flow.request.method,
            url=flow.request.pretty_url,
            headers=_headers_to_dict(flow.request.headers),
            body=_body_to_str(flow.request.content),
            http_version=flow.request.http_version,
            timestamp=time.time(),
        )

        recorded = Flow(
            id=flow_id,
            request=req,
            host=host,
            path=parsed.path or "/",
            timestamp=time.time(),
        )
        state.add_flow(recorded)

        # SSE broadcast — new flow
        try:
            from api import sse_broadcast
            sse_broadcast("flow", {
                "id": flow_id, "method": req.method, "url": req.url,
                "host": host, "path": parsed.path or "/", "timestamp": recorded.timestamp,
            })
        except Exception:
            pass

        # CSRF auto-injection
        try:
            from csrf_tracker import inject_into_request
            new_headers, new_body = inject_into_request(
                host, req.method, _headers_to_dict(flow.request.headers), _body_to_str(flow.request.content)
            )
            for k, v in new_headers.items():
                flow.request.headers[k] = v
            if new_body is not None and new_body != _body_to_str(flow.request.content):
                flow.request.content = new_body.encode("utf-8")
                recorded.request.headers = _headers_to_dict(flow.request.headers)
                recorded.request.body = new_body
        except Exception:
            pass

        # Extension request hooks
        try:
            from extensions import run_request_hooks
            run_request_hooks(recorded)
        except Exception:
            pass

        # Conditional intercept (Task #20) — use breakpoint rules
        if state.should_intercept(host, parsed.path or "/", req.method, "request"):
            event = state.add_to_intercept_queue(recorded)
            log.info(f"[intercept] Holding flow {flow_id}: {req.method} {req.url}")

            try:
                await asyncio.wait_for(event.wait(), timeout=300)
            except asyncio.TimeoutError:
                log.warning(f"[intercept] Flow {flow_id} timed out, forwarding")
                state.resolve_intercept(flow_id, "forward")

            action = state.get_intercept_action(flow_id)
            if action and action["action"] == "drop":
                log.info(f"[intercept] Dropping flow {flow_id}")
                flow.kill()
                return

            if action and action.get("modifications"):
                mods = action["modifications"]
                if mods.get("method"):
                    flow.request.method = mods["method"]
                if mods.get("url"):
                    flow.request.url = mods["url"]
                if mods.get("headers"):
                    for k, v in mods["headers"].items():
                        flow.request.headers[k] = v
                if "body" in mods:
                    body_val = mods["body"]
                    flow.request.content = body_val.encode("utf-8") if body_val else b""

                recorded.request.method = flow.request.method
                recorded.request.url = flow.request.pretty_url
                recorded.request.headers = _headers_to_dict(flow.request.headers)
                recorded.request.body = _body_to_str(flow.request.content)

    async def response(self, flow: http.HTTPFlow) -> None:
        flow_id = flow.metadata.get("proxy_engine_id")
        if not flow_id:
            return

        recorded = state.get_flow(flow_id)
        if not recorded:
            return

        host = recorded.host

        # Apply match & replace rules (response phase) — scope-aware
        try:
            import match_replace
            if match_replace.rules:
                resp_headers = _headers_to_dict(flow.response.headers)
                resp_body = _body_to_str(flow.response.content)

                _, resp_headers, resp_body = match_replace.apply_response_rules(
                    flow.response.status_code, resp_headers, resp_body, host=host,
                )

                flow.response.headers.clear()
                for k, v in resp_headers.items():
                    flow.response.headers[k] = v
                if resp_body is not None:
                    flow.response.content = resp_body.encode("utf-8")
        except Exception as e:
            log.debug(f"[match_replace] Response rule error: {e}")

        recorded.response = FlowResponse(
            status_code=flow.response.status_code,
            reason=flow.response.reason or "",
            headers=_headers_to_dict(flow.response.headers),
            body=_body_to_str(flow.response.content),
            timestamp=time.time(),
        )

        # Cookie jar — extract Set-Cookie headers
        try:
            from cookie_jar import jar
            resp_headers = _headers_to_dict(flow.response.headers)
            for k, v in resp_headers.items():
                if k.lower() == "set-cookie":
                    jar.update_from_response(flow.request.pretty_url, {k: v})
        except Exception:
            pass

        # CSRF token extraction
        try:
            from csrf_tracker import extract_from_response
            extract_from_response(host, recorded.response.headers, recorded.response.body)
        except Exception:
            pass

        # Macro recorder — append flow ID if recording
        try:
            from macro_recorder import is_recording, record_flow
            if is_recording():
                record_flow(flow_id)
        except Exception:
            pass

        # SSE broadcast — notify connected web UI clients
        try:
            from api import sse_broadcast
            sse_broadcast("flow_update", {
                "id": flow_id,
                "status_code": recorded.response.status_code,
                "content_type": recorded.response.headers.get("content-type", ""),
                "length": len(recorded.response.body) if recorded.response.body else 0,
            })
        except Exception:
            pass

        # Conditional response intercept (Task #20)
        if state.should_intercept(host, recorded.path, recorded.request.method, "response"):
            event = state.add_to_response_intercept(recorded)
            log.info(f"[intercept] Holding response {flow_id}: {flow.response.status_code}")

            try:
                await asyncio.wait_for(event.wait(), timeout=300)
            except asyncio.TimeoutError:
                log.warning(f"[intercept] Response {flow_id} timed out, forwarding")
                state.resolve_response_intercept(flow_id, "forward")

            action = state.get_response_intercept_action(flow_id)
            if action and action.get("modifications"):
                mods = action["modifications"]
                if mods.get("status_code"):
                    flow.response.status_code = int(mods["status_code"])
                if mods.get("headers"):
                    for k, v in mods["headers"].items():
                        flow.response.headers[k] = v
                if "body" in mods:
                    body_val = mods["body"]
                    flow.response.content = body_val.encode("utf-8") if body_val else b""

                recorded.response = FlowResponse(
                    status_code=flow.response.status_code,
                    reason=flow.response.reason or "",
                    headers=_headers_to_dict(flow.response.headers),
                    body=_body_to_str(flow.response.content),
                    timestamp=time.time(),
                )

        # Extension response hooks
        try:
            from extensions import run_response_hooks
            run_response_hooks(recorded)
        except Exception:
            pass

        # Live audit — auto-scan flows through proxy
        try:
            import live_audit
            if live_audit.enabled:
                await live_audit.audit_flow(recorded)
        except Exception:
            pass

        # Run passive scanner
        try:
            import passive_scanner
            if passive_scanner.enabled:
                passive_scanner.scan_flow(recorded)
        except Exception:
            pass

        # Run extension passive checks
        try:
            import extensions
            ext_findings = extensions.run_passive_checks(recorded)
            if ext_findings:
                import passive_scanner as ps
                ps.findings.extend(ext_findings)
        except Exception:
            pass

        # Check session handler for token refresh triggers
        try:
            import session_handler
            if session_handler.rules and recorded.response:
                asyncio.ensure_future(session_handler.check_and_refresh(
                    recorded.host,
                    recorded.response.status_code,
                    recorded.response.body or "",
                ))
        except Exception:
            pass

    async def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Capture WebSocket messages, with optional interception."""
        flow_id = flow.metadata.get("proxy_engine_id")
        if not flow_id:
            return

        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]

        ws_msg = WebSocketMessage(
            flow_id=flow_id,
            direction="send" if msg.from_client else "receive",
            content=msg.text if msg.is_text else f"<binary {len(msg.content)} bytes>",
            is_text=msg.is_text,
            timestamp=time.time(),
            length=len(msg.content),
        )
        state.add_ws_message(ws_msg)

        # WebSocket interception
        if state.ws_intercept_enabled:
            event = state.add_to_ws_intercept(ws_msg)
            log.info(f"[ws-intercept] Holding WS message for flow {flow_id}")
            try:
                await asyncio.wait_for(event.wait(), timeout=300)
            except asyncio.TimeoutError:
                pass

            # Check action
            for mid in list(state.ws_intercept_queue.keys()):
                action = state.get_ws_intercept_action(mid)
                if action:
                    if action["action"] == "drop":
                        msg.drop()
                        log.info(f"[ws-intercept] Dropped WS message")
                        return
                    if action.get("content") and msg.is_text:
                        msg.text = action["content"]
                        log.info(f"[ws-intercept] Modified WS message")
                break


addons = [ProxyAddon()]
