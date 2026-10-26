"""security review and guidance-gap reporting."""

def find_defects(guidance: str) -> list[dict]:
    text = guidance.lower()
    defects = []
    if "rotate" not in text:
        defects.append({"type": "missing_control", "title": "no credential rotation guidance", "severity": "high"})
    if "least privilege" not in text:
        defects.append({"type": "guidance_gap", "title": "least privilege is not stated", "severity": "medium"})
    if "owner" not in text:
        defects.append({"type": "operational_gap", "title": "no accountable owner", "severity": "medium"})
    return defects
