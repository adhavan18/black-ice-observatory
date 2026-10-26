"""explainable behavioral profiling, not autonomous malware classification."""

from dataclasses import dataclass


@dataclass(frozen=True)
class behavior_profile:
    execution: float
    persistence: float
    collection: float
    exfiltration: float
    confidence: float

    def as_dict(self) -> dict[str, float]:
        return self.__dict__.copy()


def profile(events: list[str]) -> behavior_profile:
    """score synthetic event labels using auditable feature weights."""
    labels = {event.lower() for event in events}
    execution = min(1.0, 0.35 * bool(labels & {"script", "child_process", "scripting"}) + 0.55 * bool("encoded_command" in labels))
    persistence = 0.8 if labels & {"scheduled_task", "startup_item"} else 0.05
    collection = min(1.0, 0.5 * bool(labels & {"archive", "clipboard", "browser_data"}) + 0.3 * bool("file_discovery" in labels))
    exfiltration = 0.85 if labels & {"large_upload", "rare_destination"} else 0.05
    confidence = min(0.99, 0.45 + 0.12 * len(labels))
    return behavior_profile(execution, persistence, collection, exfiltration, confidence)
