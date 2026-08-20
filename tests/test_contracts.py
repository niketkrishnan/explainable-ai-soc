from soc_detector import SecurityEvent


def test_public_entry_point_imports():
    assert SecurityEvent is not None
