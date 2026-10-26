from black_ice.behavior import profile


def test_behavior_profile_is_bounded():
    result = profile(["script", "encoded_command", "large_upload"])
    assert 0 <= result.execution <= 1
    assert result.exfiltration > 0
