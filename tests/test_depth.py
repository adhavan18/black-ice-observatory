from black_ice.detector import detect
from black_ice.disasm import disassemble_x86
from black_ice.pipeline import partitioned_load

def test_scored_detector_requires_features():
    assert detect("powershell -enc", {"script": True})["verdict"] == "medium"
    assert detect("powershell -enc", {"script": False})["verdict"] == "low"

def test_safe_disassembler_returns_instructions():
    result = disassemble_x86(bytes.fromhex("554889e5b878563412c390"))
    assert result[0]["mnemonic"] == "push rbp"
    assert result[1]["mnemonic"] == "mov rbp, rsp"
    assert result[-1]["mnemonic"] == "nop"

def test_partitioned_load_reports_throughput():
    result = partitioned_load([{"report_id": str(i), "tenant": str(i % 3)} for i in range(100)])
    assert result["processed"] == 100
    assert result["reports_per_second"] > 0
