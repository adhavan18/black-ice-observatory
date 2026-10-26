"""join analysis, intelligence, detection, and response into one case artifact."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from .analysis import detect_signatures, extract_indicators
from .behavior import profile
from .detector import detect
from .intelligence import intelligence_requirements, report
from .response import first_party_mitigations, plan

@dataclass(frozen=True)
class case_result:
    case_id: str
    created_at: str
    severity: str
    indicators: list[dict]
    signatures: list[str]
    scored_detection: dict
    behavior: dict
    intelligence_requirements: list[str]
    response: dict
    mitigations: list[str]
    def json(self) -> dict: return asdict(self)

def create_case(case_id: str, payload: dict) -> case_result:
    text = str(payload); events = payload.get("events", [])
    intel = report(case_id, payload.get("source", "unknown"), payload.get("actor", "unknown"), payload.get("title", ""), [], payload.get("techniques", []), float(payload.get("confidence", 0.5)), payload.get("requirements", []))
    scored = detect(text, {"script": "script" in events, "document": payload.get("file_type") == "document"})
    severity = "critical" if scored["score"] >= 0.8 else "high" if scored["score"] >= 0.45 else "medium" if scored["score"] >= 0.2 else "low"
    return case_result(case_id, datetime.now(timezone.utc).isoformat(), severity, [item.json() for item in extract_indicators(text)], detect_signatures(text), scored, profile(events).as_dict(), intelligence_requirements([intel]), plan(severity, []), first_party_mitigations(payload.get("service", "the affected service")))
