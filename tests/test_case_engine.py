from black_ice.case_engine import create_case

def test_case_engine_creates_a_reviewable_artifact():
    result = create_case("case-42", {"source": "internal", "actor": "aurora-lynx", "events": ["script", "encoded_command", "large_upload"], "requirements": ["confirm infrastructure ownership"], "service": "payments-api"})
    assert result.case_id == "case-42"
    assert result.severity in {"medium", "high", "critical"}
    assert result.response["approval_required"] is True
    assert result.mitigations[0].startswith("review payments-api")
