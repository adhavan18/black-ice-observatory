import argparse
import json
from pathlib import Path

from .analysis import detect_signatures, extract_indicators
from .behavior import profile


def main() -> None:
    parser = argparse.ArgumentParser(prog="black-ice")
    parser.add_argument("command", choices=["analyze", "landscape"])
    parser.add_argument("report")
    args = parser.parse_args()
    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    text = json.dumps(data)
    result = {"case": data.get("case_id"), "indicators": [item.json() for item in extract_indicators(text)], "signature_hits": detect_signatures(text), "behavior": profile(data.get("events", [])).as_dict()}
    print(json.dumps(result, indent=2))
