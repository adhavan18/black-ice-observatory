import re
from pathlib import Path

SECRET_PATTERNS = {"aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"), "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "token_assignment": re.compile(r"(?i)(?:token|secret|password)\s*[:=]\s*['\"][^'\"]{8,}")}

def scan_path(root: str) -> list[dict]:
    findings = []
    for path in Path(root).rglob("*"):
        if not path.is_file() or any(part in {".git", ".venv", "__pycache__"} for part in path.parts):
            continue
        try: text = path.read_text(errors="ignore")
        except OSError: continue
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text): findings.append({"file": str(path), "type": name, "severity": "high"})
        if "print(" in text and any(word in text.lower() for word in ("token", "password", "secret")):
            findings.append({"file": str(path), "type": "unsafe_logging", "severity": "medium"})
    return findings
