"""normalize reports and track adversaries with source-aware confidence."""

from dataclasses import dataclass, field


@dataclass
class report:
    report_id: str
    source: str
    actor: str
    title: str
    indicators: list[str]
    techniques: list[str]
    confidence: float
    requirements: list[str] = field(default_factory=list)


@dataclass
class actor_record:
    name: str
    aliases: set[str] = field(default_factory=set)
    campaigns: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    reports: int = 0
    confidence: float = 0.0


def track(reports: list[report]) -> dict[str, actor_record]:
    actors: dict[str, actor_record] = {}
    for item in reports:
        current = actors.setdefault(item.actor, actor_record(item.actor))
        current.reports += 1
        current.techniques.update(item.techniques)
        current.confidence = max(current.confidence, item.confidence)
    return actors


def intelligence_requirements(reports: list[report]) -> list[str]:
    return sorted({requirement for item in reports for requirement in item.requirements})
