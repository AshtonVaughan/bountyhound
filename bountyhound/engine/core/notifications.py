"""
Webhook-Based Notification System

Provides Slack, Discord, and generic webhook notifications for:
- New findings discovered during hunts
- Hunt start/completion events
- Target monitor alerts (endpoint changes, new features)
- Errors during hunt phases

Configuration is stored in C:/Users/vaugh/BountyHound/database/notifications.json.
Webhook delivery uses subprocess+curl for reliability and minimal dependencies.

Usage:
    from engine.core.notifications import NotificationManager

    mgr = NotificationManager()

    # Add webhooks
    mgr.add_webhook(NotificationService.SLACK, "https://hooks.slack.com/services/T.../B.../xxx")
    mgr.add_webhook(NotificationService.DISCORD, "https://discord.com/api/webhooks/123/abc")

    # Notify on finding
    mgr.notify_finding({
        "title": "IDOR on /api/users/{id}",
        "severity": "HIGH",
        "target": "example.com",
        "vuln_type": "IDOR",
        "evidence": "Accessed user 42 data with user 1 token"
    })

    # Notify hunt lifecycle
    mgr.notify_hunt_start("example.com", "hunt-20260218-001")
    mgr.notify_hunt_complete("example.com", findings_count=3, summary="2 HIGH, 1 MEDIUM")
"""

import json
import subprocess
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from engine.core.config import BountyHoundConfig


logger = logging.getLogger("bountyhound.notifications")

CONFIG_PATH = BountyHoundConfig.NOTIFICATIONS_CONFIG

# Severity-to-color mapping for Slack and Discord embeds
SEVERITY_COLORS = {
    "CRITICAL": {"slack": "#FF0000", "discord": 0xFF0000},
    "HIGH":     {"slack": "#FF6600", "discord": 0xFF6600},
    "MEDIUM":   {"slack": "#FFCC00", "discord": 0xFFCC00},
    "LOW":      {"slack": "#00CC00", "discord": 0x00CC00},
    "INFO":     {"slack": "#0066FF", "discord": 0x0066FF},
    "UNKNOWN":  {"slack": "#999999", "discord": 0x999999},
}

# Severity emoji for message headers
SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":large_orange_diamond:",
    "LOW": ":large_blue_diamond:",
    "INFO": ":information_source:",
    "UNKNOWN": ":grey_question:",
}


class NotificationService(Enum):
    """Supported notification services."""
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"


@dataclass
class NotificationConfig:
    """Configuration for a single notification webhook."""
    service: str          # NotificationService value (slack, discord, webhook)
    webhook_url: str      # Full webhook URL
    enabled: bool = True  # Whether this webhook is active
    channel: Optional[str] = None    # Override channel (Slack only)
    username: Optional[str] = None   # Override username/bot name


class NotificationManager:
    """
    Manages webhook-based notifications for BountyHound.

    Sends formatted messages to Slack, Discord, and generic webhooks
    when findings are discovered, hunts start/complete, alerts trigger,
    or errors occur.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize NotificationManager and load webhook config.

        Args:
            config_path: Override path for notifications.json (default uses CONFIG_PATH)
        """
        self._config_path = Path(config_path) if config_path else CONFIG_PATH
        self._webhooks: List[NotificationConfig] = []
        self._load_config()

    # ------------------------------------------------------------------ #
    #  Configuration management
    # ------------------------------------------------------------------ #

    def _load_config(self):
        """Load webhook configurations from JSON file."""
        if not self._config_path.exists():
            self._webhooks = []
            return

        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self._webhooks = []
            for entry in data.get("webhooks", []):
                self._webhooks.append(NotificationConfig(
                    service=entry["service"],
                    webhook_url=entry["webhook_url"],
                    enabled=entry.get("enabled", True),
                    channel=entry.get("channel"),
                    username=entry.get("username"),
                ))

        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to load notification config from %s: %s", self._config_path, exc)
            self._webhooks = []

    def _save_config(self):
        """Persist current webhook configurations to JSON file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "webhooks": [asdict(w) for w in self._webhooks],
            "updated_at": datetime.now().isoformat(),
        }

        with open(self._config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def add_webhook(
        self,
        service: NotificationService,
        webhook_url: str,
        channel: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Add (or update) a notification webhook.

        If a webhook for the given service already exists it is replaced.

        Args:
            service: NotificationService enum member
            webhook_url: Full webhook URL
            channel: Optional channel override (Slack)
            username: Optional bot name override

        Returns:
            Status dict with success flag and message
        """
        # Remove existing webhook for this service (replace semantics)
        self._webhooks = [w for w in self._webhooks if w.service != service.value]

        config = NotificationConfig(
            service=service.value,
            webhook_url=webhook_url,
            enabled=True,
            channel=channel,
            username=username or "BountyHound",
        )
        self._webhooks.append(config)
        self._save_config()

        logger.info("Added %s webhook", service.value)
        return {"success": True, "message": f"{service.value} webhook configured"}

    def remove_webhook(self, service: NotificationService) -> Dict[str, Any]:
        """
        Remove a webhook for the given service.

        Args:
            service: NotificationService enum member

        Returns:
            Status dict with success flag and message
        """
        before = len(self._webhooks)
        self._webhooks = [w for w in self._webhooks if w.service != service.value]

        if len(self._webhooks) == before:
            return {"success": False, "message": f"No {service.value} webhook found"}

        self._save_config()
        logger.info("Removed %s webhook", service.value)
        return {"success": True, "message": f"{service.value} webhook removed"}

    def status(self) -> Dict[str, Any]:
        """
        Return configured services and their enabled/disabled status.

        Returns:
            Dict with list of services and overall counts
        """
        services = []
        for w in self._webhooks:
            services.append({
                "service": w.service,
                "enabled": w.enabled,
                "channel": w.channel,
                "username": w.username,
                "url_preview": w.webhook_url[:40] + "..." if len(w.webhook_url) > 40 else w.webhook_url,
            })

        return {
            "total_webhooks": len(self._webhooks),
            "enabled": sum(1 for w in self._webhooks if w.enabled),
            "disabled": sum(1 for w in self._webhooks if not w.enabled),
            "services": services,
        }

    # ------------------------------------------------------------------ #
    #  Notification entry points
    # ------------------------------------------------------------------ #

    def notify_finding(self, finding_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notification about a new finding.

        Args:
            finding_dict: Finding data with keys:
                - title (str): Finding title
                - severity (str): CRITICAL / HIGH / MEDIUM / LOW / INFO
                - target (str): Target domain
                - vuln_type (str): Vulnerability type (IDOR, XSS, etc.)
                - evidence (str, optional): Evidence preview snippet
                - url (str, optional): Affected URL/endpoint
                - payout_estimate (str, optional): Estimated bounty

        Returns:
            Dict with delivery results per service
        """
        title = finding_dict.get("title", "Untitled Finding")
        severity = finding_dict.get("severity", "UNKNOWN").upper()
        target = finding_dict.get("target", "unknown")
        vuln_type = finding_dict.get("vuln_type", "Unknown")
        evidence = finding_dict.get("evidence", "")
        url = finding_dict.get("url", "")
        payout_estimate = finding_dict.get("payout_estimate", "")

        # Truncate evidence for notification preview
        evidence_preview = (evidence[:200] + "...") if len(evidence) > 200 else evidence

        payload = {
            "event": "finding",
            "title": title,
            "severity": severity,
            "target": target,
            "vuln_type": vuln_type,
            "evidence_preview": evidence_preview,
            "url": url,
            "payout_estimate": payout_estimate,
            "timestamp": datetime.now().isoformat(),
        }

        return self._dispatch(payload)

    def notify_hunt_start(self, target: str, hunt_id: str) -> Dict[str, Any]:
        """
        Notify that a hunt has started.

        Args:
            target: Target domain
            hunt_id: Unique hunt identifier

        Returns:
            Dict with delivery results per service
        """
        payload = {
            "event": "hunt_start",
            "target": target,
            "hunt_id": hunt_id,
            "timestamp": datetime.now().isoformat(),
        }
        return self._dispatch(payload)

    def notify_hunt_complete(
        self,
        target: str,
        findings_count: int,
        summary: str,
    ) -> Dict[str, Any]:
        """
        Notify that a hunt has completed.

        Args:
            target: Target domain
            findings_count: Number of findings discovered
            summary: Human-readable summary (e.g. "2 HIGH, 1 MEDIUM, 0 LOW")

        Returns:
            Dict with delivery results per service
        """
        payload = {
            "event": "hunt_complete",
            "target": target,
            "findings_count": findings_count,
            "summary": summary,
            "timestamp": datetime.now().isoformat(),
        }
        return self._dispatch(payload)

    def notify_alert(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Forward a target-monitor alert (endpoint changes, new features, etc.).

        Args:
            alert_dict: Alert data with keys:
                - target (str): Target domain
                - alert_type (str): e.g. "new_endpoint", "tech_stack_change"
                - details (str): Human-readable description
                - changes (dict, optional): Structured change data

        Returns:
            Dict with delivery results per service
        """
        payload = {
            "event": "alert",
            "target": alert_dict.get("target", "unknown"),
            "alert_type": alert_dict.get("alert_type", "general"),
            "details": alert_dict.get("details", ""),
            "changes": alert_dict.get("changes", {}),
            "timestamp": datetime.now().isoformat(),
        }
        return self._dispatch(payload)

    def notify_error(self, phase: str, error_message: str) -> Dict[str, Any]:
        """
        Notify about an error that occurred during a hunt phase.

        Args:
            phase: Hunt phase where the error occurred (e.g. "recon", "testing", "sync")
            error_message: Error description

        Returns:
            Dict with delivery results per service
        """
        payload = {
            "event": "error",
            "phase": phase,
            "error_message": error_message,
            "timestamp": datetime.now().isoformat(),
        }
        return self._dispatch(payload)

    # ------------------------------------------------------------------ #
    #  Dispatch and delivery
    # ------------------------------------------------------------------ #

    def _dispatch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route a payload to all enabled webhooks.

        Args:
            payload: Normalized event payload

        Returns:
            Dict mapping service names to delivery results
        """
        results: Dict[str, Any] = {}

        for webhook in self._webhooks:
            if not webhook.enabled:
                results[webhook.service] = {"sent": False, "reason": "disabled"}
                continue

            try:
                if webhook.service == NotificationService.SLACK.value:
                    ok = self._send_slack(payload, webhook)
                elif webhook.service == NotificationService.DISCORD.value:
                    ok = self._send_discord(payload, webhook)
                else:
                    ok = self._send_generic(payload, webhook)

                results[webhook.service] = {"sent": ok}

            except Exception as exc:
                logger.error("Failed to send %s notification: %s", webhook.service, exc)
                results[webhook.service] = {"sent": False, "error": str(exc)}

        return results

    # ------------------------------------------------------------------ #
    #  Slack formatting (Block Kit)
    # ------------------------------------------------------------------ #

    def _send_slack(self, payload: Dict[str, Any], webhook: NotificationConfig) -> bool:
        """
        Format payload as Slack Block Kit message and send via webhook.

        Args:
            payload: Normalized event payload
            webhook: Slack webhook configuration

        Returns:
            True if delivery succeeded (HTTP 2xx)
        """
        event = payload.get("event", "unknown")

        if event == "finding":
            message = self._format_slack_finding(payload, webhook)
        elif event == "hunt_start":
            message = self._format_slack_hunt_start(payload, webhook)
        elif event == "hunt_complete":
            message = self._format_slack_hunt_complete(payload, webhook)
        elif event == "alert":
            message = self._format_slack_alert(payload, webhook)
        elif event == "error":
            message = self._format_slack_error(payload, webhook)
        else:
            message = self._format_slack_generic(payload, webhook)

        return self._curl_post(webhook.webhook_url, message)

    def _format_slack_finding(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Slack Block Kit payload for a finding notification."""
        severity = payload.get("severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])["slack"]
        emoji = SEVERITY_EMOJI.get(severity, ":grey_question:")

        fields = [
            {"type": "mrkdwn", "text": f"*Severity:*\n{emoji} {severity}"},
            {"type": "mrkdwn", "text": f"*Type:*\n{payload.get('vuln_type', 'N/A')}"},
            {"type": "mrkdwn", "text": f"*Target:*\n`{payload.get('target', 'N/A')}`"},
        ]

        if payload.get("payout_estimate"):
            fields.append({"type": "mrkdwn", "text": f"*Est. Payout:*\n{payload['payout_estimate']}"})

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"New Finding: {payload.get('title', 'Untitled')}",
                    "emoji": True,
                },
            },
            {"type": "section", "fields": fields},
        ]

        if payload.get("url"):
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Endpoint:*\n`{payload['url']}`"},
            })

        if payload.get("evidence_preview"):
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Evidence:*\n```{payload['evidence_preview']}```",
                },
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"BountyHound | {payload.get('timestamp', '')}"},
            ],
        })

        message: Dict[str, Any] = {
            "attachments": [{
                "color": color,
                "blocks": blocks,
            }],
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_slack_hunt_start(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Slack Block Kit payload for hunt start."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Hunt Started", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{payload.get('target', 'N/A')}`"},
                    {"type": "mrkdwn", "text": f"*Hunt ID:*\n`{payload.get('hunt_id', 'N/A')}`"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"BountyHound | {payload.get('timestamp', '')}"},
                ],
            },
        ]

        message: Dict[str, Any] = {
            "attachments": [{"color": "#0066FF", "blocks": blocks}],
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_slack_hunt_complete(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Slack Block Kit payload for hunt completion."""
        count = payload.get("findings_count", 0)
        color = "#00CC00" if count > 0 else "#999999"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Hunt Complete", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{payload.get('target', 'N/A')}`"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{count}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{payload.get('summary', 'No summary')}"},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"BountyHound | {payload.get('timestamp', '')}"},
                ],
            },
        ]

        message: Dict[str, Any] = {
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_slack_alert(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Slack Block Kit payload for a monitor alert."""
        details = payload.get("details", "No details")
        changes = payload.get("changes", {})
        changes_text = json.dumps(changes, indent=2) if changes else "N/A"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Target Alert", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n`{payload.get('target', 'N/A')}`"},
                    {"type": "mrkdwn", "text": f"*Alert Type:*\n{payload.get('alert_type', 'general')}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:*\n{details}"},
            },
        ]

        if changes:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Changes:*\n```{changes_text}```"},
            })

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"BountyHound | {payload.get('timestamp', '')}"},
            ],
        })

        message: Dict[str, Any] = {
            "attachments": [{"color": "#FFCC00", "blocks": blocks}],
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_slack_error(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Slack Block Kit payload for an error notification."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Hunt Error", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Phase:*\n`{payload.get('phase', 'unknown')}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error:*\n```{payload.get('error_message', 'Unknown error')}```",
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"BountyHound | {payload.get('timestamp', '')}"},
                ],
            },
        ]

        message: Dict[str, Any] = {
            "attachments": [{"color": "#FF0000", "blocks": blocks}],
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_slack_generic(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Fallback Slack formatter for unrecognized event types."""
        text = json.dumps(payload, indent=2, default=str)

        message: Dict[str, Any] = {
            "text": f"BountyHound event:\n```{text}```",
        }

        if webhook.channel:
            message["channel"] = webhook.channel
        if webhook.username:
            message["username"] = webhook.username

        return message

    # ------------------------------------------------------------------ #
    #  Discord formatting (embeds)
    # ------------------------------------------------------------------ #

    def _send_discord(self, payload: Dict[str, Any], webhook: NotificationConfig) -> bool:
        """
        Format payload as Discord embed message and send via webhook.

        Args:
            payload: Normalized event payload
            webhook: Discord webhook configuration

        Returns:
            True if delivery succeeded (HTTP 2xx)
        """
        event = payload.get("event", "unknown")

        if event == "finding":
            message = self._format_discord_finding(payload, webhook)
        elif event == "hunt_start":
            message = self._format_discord_hunt_start(payload, webhook)
        elif event == "hunt_complete":
            message = self._format_discord_hunt_complete(payload, webhook)
        elif event == "alert":
            message = self._format_discord_alert(payload, webhook)
        elif event == "error":
            message = self._format_discord_error(payload, webhook)
        else:
            message = self._format_discord_generic(payload, webhook)

        return self._curl_post(webhook.webhook_url, message)

    def _format_discord_finding(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Discord embed payload for a finding notification."""
        severity = payload.get("severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])["discord"]

        fields = [
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Type", "value": payload.get("vuln_type", "N/A"), "inline": True},
            {"name": "Target", "value": f"`{payload.get('target', 'N/A')}`", "inline": True},
        ]

        if payload.get("url"):
            fields.append({"name": "Endpoint", "value": f"`{payload['url']}`", "inline": False})

        if payload.get("payout_estimate"):
            fields.append({"name": "Est. Payout", "value": payload["payout_estimate"], "inline": True})

        if payload.get("evidence_preview"):
            fields.append({
                "name": "Evidence",
                "value": f"```\n{payload['evidence_preview']}\n```",
                "inline": False,
            })

        embed = {
            "title": f"New Finding: {payload.get('title', 'Untitled')}",
            "color": color,
            "fields": fields,
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_discord_hunt_start(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Discord embed payload for hunt start."""
        embed = {
            "title": "Hunt Started",
            "color": 0x0066FF,
            "fields": [
                {"name": "Target", "value": f"`{payload.get('target', 'N/A')}`", "inline": True},
                {"name": "Hunt ID", "value": f"`{payload.get('hunt_id', 'N/A')}`", "inline": True},
            ],
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_discord_hunt_complete(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Discord embed payload for hunt completion."""
        count = payload.get("findings_count", 0)
        color = 0x00CC00 if count > 0 else 0x999999

        embed = {
            "title": "Hunt Complete",
            "color": color,
            "fields": [
                {"name": "Target", "value": f"`{payload.get('target', 'N/A')}`", "inline": True},
                {"name": "Findings", "value": str(count), "inline": True},
                {"name": "Summary", "value": payload.get("summary", "No summary"), "inline": False},
            ],
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_discord_alert(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Discord embed payload for a monitor alert."""
        changes = payload.get("changes", {})
        changes_text = json.dumps(changes, indent=2) if changes else "N/A"

        fields = [
            {"name": "Target", "value": f"`{payload.get('target', 'N/A')}`", "inline": True},
            {"name": "Alert Type", "value": payload.get("alert_type", "general"), "inline": True},
            {"name": "Details", "value": payload.get("details", "No details"), "inline": False},
        ]

        if changes:
            fields.append({
                "name": "Changes",
                "value": f"```json\n{changes_text}\n```",
                "inline": False,
            })

        embed = {
            "title": "Target Alert",
            "color": 0xFFCC00,
            "fields": fields,
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_discord_error(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Build Discord embed payload for an error notification."""
        embed = {
            "title": "Hunt Error",
            "color": 0xFF0000,
            "fields": [
                {"name": "Phase", "value": f"`{payload.get('phase', 'unknown')}`", "inline": True},
                {
                    "name": "Error",
                    "value": f"```\n{payload.get('error_message', 'Unknown error')}\n```",
                    "inline": False,
                },
            ],
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    def _format_discord_generic(self, payload: Dict[str, Any], webhook: NotificationConfig) -> Dict:
        """Fallback Discord formatter for unrecognized event types."""
        embed = {
            "title": "BountyHound Event",
            "color": 0x999999,
            "description": f"```json\n{json.dumps(payload, indent=2, default=str)}\n```",
            "footer": {"text": "BountyHound"},
            "timestamp": payload.get("timestamp", datetime.now().isoformat()),
        }

        message: Dict[str, Any] = {"embeds": [embed]}

        if webhook.username:
            message["username"] = webhook.username

        return message

    # ------------------------------------------------------------------ #
    #  Generic webhook
    # ------------------------------------------------------------------ #

    def _send_generic(self, payload: Dict[str, Any], webhook: NotificationConfig) -> bool:
        """
        Send raw JSON payload to a generic webhook URL.

        Args:
            payload: Normalized event payload (sent as-is)
            webhook: Webhook configuration

        Returns:
            True if delivery succeeded (HTTP 2xx)
        """
        message = {
            "source": "bountyhound",
            "username": webhook.username or "BountyHound",
            **payload,
        }
        return self._curl_post(webhook.webhook_url, message)

    # ------------------------------------------------------------------ #
    #  HTTP delivery via subprocess + curl
    # ------------------------------------------------------------------ #

    def _curl_post(self, url: str, data: Dict[str, Any]) -> bool:
        """
        POST JSON data to a URL using subprocess + curl.

        Args:
            url: Destination webhook URL
            data: JSON-serializable dict to send as POST body

        Returns:
            True if curl returned exit code 0 and HTTP status was 2xx
        """
        json_body = json.dumps(data, ensure_ascii=False, default=str)

        cmd = [
            "curl",
            "-s",                       # Silent mode
            "-o", "/dev/null",          # Discard response body
            "-w", "%{http_code}",       # Print only HTTP status code
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", json_body,
            "--max-time", "10",         # 10 second timeout
            url,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )

            http_code = result.stdout.strip()

            if result.returncode != 0:
                logger.warning(
                    "curl failed for %s (exit %d): %s",
                    url[:50], result.returncode, result.stderr.strip(),
                )
                return False

            if http_code.startswith("2"):
                logger.debug("Webhook delivered to %s (HTTP %s)", url[:50], http_code)
                return True
            else:
                logger.warning("Webhook to %s returned HTTP %s", url[:50], http_code)
                return False

        except subprocess.TimeoutExpired:
            logger.error("curl timed out posting to %s", url[:50])
            return False
        except FileNotFoundError:
            logger.error("curl not found on PATH -- cannot deliver webhook")
            return False
        except Exception as exc:
            logger.error("Unexpected error posting to %s: %s", url[:50], exc)
            return False
