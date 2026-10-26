"""scored detection rules with regex and metadata predicates."""
import re

RULES = [
    {"name": "encoded_script_chain", "weight": 0.45, "patterns": [r"powershell\s+-enc", r"frombase64string"], "requires": ["script"]},
    {"name": "suspicious_document_drop", "weight": 0.35, "patterns": [r"auto(?:open|_open)", r"writebytes"], "requires": ["document"]},
    {"name": "rare_exfiltration_path", "weight": 0.40, "patterns": [r"large_upload", r"rare_destination", r"https?://"], "requires": []},
]

def detect(text: str, features: dict | None = None) -> dict:
    lowered = text.lower(); features = features or {}; hits = []
    for rule in RULES:
        matches = [pattern for pattern in rule["patterns"] if re.search(pattern, lowered)]
        if matches and all(features.get(key, False) for key in rule["requires"]):
            hits.append({"rule": rule["name"], "weight": rule["weight"], "evidence": matches})
    score = min(1.0, sum(item["weight"] for item in hits))
    return {"score": round(score, 3), "verdict": "high" if score >= 0.7 else "medium" if score >= 0.35 else "low", "hits": hits}
