"""Example passive scanner extension.

To create a custom check:
1. Create a .py file in the extensions/ directory
2. Define NAME, DESCRIPTION, CHECK_TYPE ("passive" or "active"), ENABLED
3. For passive: define passive_check(flow) -> list[PassiveFinding]
4. For active: define async active_check(url) -> list[ScanFinding]
"""

from models import Flow, PassiveFinding

NAME = "example-check"
DESCRIPTION = "Example: detect debug mode indicators"
CHECK_TYPE = "passive"
ENABLED = True


def passive_check(flow: Flow) -> list[PassiveFinding]:
    """Check for debug mode indicators in responses."""
    if not flow.response or not flow.response.body:
        return []

    findings = []
    debug_indicators = [
        "DEBUG = True",
        "DJANGO_DEBUG",
        "debug_toolbar",
        "Xdebug",
        "phpinfo()",
    ]

    body = flow.response.body[:5000]
    for indicator in debug_indicators:
        if indicator.lower() in body.lower():
            findings.append(PassiveFinding(
                flow_id=flow.id,
                check_id="debug-mode-indicator",
                name=f"Debug Mode Indicator: {indicator}",
                severity="medium",
                description=f"Response contains debug indicator: {indicator}",
                evidence=indicator,
                url=flow.request.url,
            ))

    return findings
