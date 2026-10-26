from black_ice.review import find_defects


def test_finds_guidance_gaps():
    defects = find_defects("report the incident")
    assert any(item["type"] == "missing_control" for item in defects)
