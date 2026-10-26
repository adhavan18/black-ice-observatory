"""defensive response plans with human approval points."""

def plan(severity: str, indicators: list[str]) -> dict:
    actions = ["preserve evidence", "open an incident record", "notify the service owner"]
    if severity.lower() in {"high", "critical"}:
        actions += ["isolate the affected host after approval", "rotate potentially exposed tokens", "hunt for the indicators across first-party telemetry"]
    return {"severity": severity, "indicators": indicators, "actions": actions, "approval_required": True}


def first_party_mitigations(service: str) -> list[str]:
    return [f"review {service} trust boundaries", "remove unnecessary permissions", "add a regression detection for the observed behavior", "document the owner and rollback path"]
