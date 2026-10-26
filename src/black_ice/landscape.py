from collections import Counter

def summarize(reports: list[dict]) -> dict:
    return {"reports": len(reports), "techniques": Counter(t for item in reports for t in item.get("techniques", [])), "sectors": Counter(item.get("sector", "unknown") for item in reports), "sources": Counter(item.get("source", "unknown") for item in reports), "actors": Counter(item.get("actor", "unknown") for item in reports)}
