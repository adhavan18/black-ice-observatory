from black_ice.intelligence import report, intelligence_requirements, track


def test_tracks_actor_and_requirements():
    items = [report("r1", "internal", "aurora-lynx", "x", [], ["execution"], 0.8, ["confirm infrastructure ownership"])]
    actors = track(items)
    assert actors["aurora-lynx"].reports == 1
    assert intelligence_requirements(items) == ["confirm infrastructure ownership"]
