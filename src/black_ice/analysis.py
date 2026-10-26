"""safe, non-executing analysis for sample metadata and synthetic observations."""

from __future__ import annotations

import hashlib
import re
import math
import struct
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


def static_file_report(path: str | Path) -> dict:
    """inspect bytes without loading them as executable code."""
    raw = Path(path).read_bytes()
    printable = "".join(chr(byte) if 32 <= byte < 127 else " " for byte in raw)
    strings = sorted(set(item for item in re.findall(r"[ -~]{5,}", printable)))[:200]
    counts = [raw.count(bytes([value])) for value in range(256)]
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / len(raw)
            entropy -= probability * math.log2(probability)
    format_name = "unknown"
    header = {}
    if raw[:2] == b"MZ":
        format_name = "pe"
        if len(raw) >= 0x40:
            pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
            header = {"pe_offset": pe_offset, "signature": raw[pe_offset:pe_offset + 4].decode("ascii", errors="replace")} if pe_offset + 4 <= len(raw) else {}
    elif raw[:4] == b"\x7fELF":
        format_name = "elf"
        header = {"class": 64 if len(raw) > 4 and raw[4] == 2 else 32, "endianness": "little" if len(raw) > 5 and raw[5] == 1 else "big"}
    return {"path": str(path), "size": len(raw), "format": format_name, "sha256": hashlib.sha256(raw).hexdigest(), "entropy": round(entropy, 4), "strings": strings, "header": header}
