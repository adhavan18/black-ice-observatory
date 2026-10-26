import argparse
import json
from pathlib import Path

from .analysis import detect_signatures, extract_indicators
from .behavior import profile
from .landscape import summarize
from .opsec import scan_path
from .vulnerability import prioritize
from .pipeline import process_reports
from .intelligence import report, intelligence_requirements


def main() -> None:
    parser = argparse.ArgumentParser(prog="black-ice")
    parser.add_argument("command", choices=["analyze", "landscape", "vulnerabilities", "opsec", "ingest"])
    parser.add_argument("report")
    args = parser.parse_args()
    if args.command == "opsec":
        print(json.dumps(scan_path(args.report), indent=2)); return
    data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    if args.command == "landscape":
        print(json.dumps(summarize(data), indent=2, default=dict)); return
    if args.command == "vulnerabilities":
        print(json.dumps(prioritize(data, {"internet-api"}), indent=2)); return
    if args.command == "ingest":
        print(json.dumps(process_reports(data), indent=2)); return
    text = json.dumps(data)
    intel = report(data.get("case_id", "unknown"), data.get("source", "unknown"), data.get("actor", "unknown"), data.get("title", ""), [], data.get("techniques", []), data.get("confidence", 0.5), data.get("requirements", []))
    result = {"case": data.get("case_id"), "indicators": [item.json() for item in extract_indicators(text)], "signature_hits": detect_signatures(text), "behavior": profile(data.get("events", [])).as_dict(), "intelligence_requirements": intelligence_requirements([intel])}
    print(json.dumps(result, indent=2))
