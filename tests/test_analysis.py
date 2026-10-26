import json
from pathlib import Path

from black_ice.analysis import detect_signatures, extract_indicators


def test_extracts_safe_indicators():
    text = Path("examples/report.json").read_text()
    values = extract_indicators(text)
    assert any(item.kind == "sha256" for item in values)
    assert any(item.kind == "url" for item in values)


def test_signature_engine_is_transparent():
    assert "encoded_command" in detect_signatures("powershell -enc")
