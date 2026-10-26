import json
from pathlib import Path
from black_ice.analysis import static_file_report
from black_ice.landscape import summarize
from black_ice.pipeline import process_reports
from black_ice.vulnerability import prioritize

def test_static_parser_reads_pe_header_without_execution(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"\x00" * 20 + b"PE\x00\x00")
    result = static_file_report(sample)
    assert result["format"] == "pe"

def test_vulnerabilities_rank_exploited_internet_asset_first():
    result = prioritize([{"cve": "a", "asset": "api", "cvss": 7, "known_exploitation": True}], {"api"})
    assert result[0]["priority"] == "critical"

def test_landscape_aggregates_reports():
    data = json.loads(Path("examples/landscape.json").read_text())
    assert summarize(data)["reports"] == 3
    assert summarize(data)["techniques"]["execution"] == 2

def test_queue_pipeline_processes_all_reports():
    result = process_reports([{"report_id": str(i), "indicators": []} for i in range(50)])
    assert len(result) == 50
