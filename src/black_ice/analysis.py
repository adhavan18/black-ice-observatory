"""safe, non-executing analysis for sample metadata and synthetic observations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, asdict
from pathlib import Path

HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL = re.compile(r"https?://[^\s\"']+")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)


@dataclass(frozen=True)
class finding:
    kind: str
    value: str
    confidence: float
    source: str

    def json(self) -> dict:
        return asdict(self)


def sha256_file(path: str | Path) -> str:
    """hash a file without opening or executing it as a program."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_indicators(text: str, source: str = "report") -> list[finding]:
    values: list[finding] = []
    for value in sorted(set(HASH.findall(text))):
        values.append(finding("sha256", value.lower(), 0.99, source))
    for value in sorted(set(URL.findall(text))):
        values.append(finding("url", value.rstrip(".,"), 0.90, source))
    for value in sorted(set(DOMAIN.findall(text))):
        if not value.lower().endswith(("example.com", "example.org")):
            values.append(finding("domain", value.lower(), 0.75, source))
    return values


def detect_signatures(text: str) -> list[str]:
    rules = {"encoded_command": ["powershell -enc", "base64", "frombase64string"], "macro_dropper": ["autoopen", "document_open", "writebytes"], "credential_access_hint": ["lsass", "browser passwords", "credential dump"]}
    lowered = text.lower()
    return [name for name, needles in rules.items() if any(needle in lowered for needle in needles)]
