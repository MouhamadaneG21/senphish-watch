from src.detector import BrandDetector
from src.monitor import Seen, handle_domains

BRANDS = [
    {"name": "Wave", "category": "mobile_money", "keywords": ["wave"],
     "official_domains": ["wave.com"]},
]


def run(domains, seen=None):
    out, stats = [], {"domains": 0, "detections": 0}
    handle_domains(domains, BrandDetector(BRANDS), seen or Seen(), out.append, stats)
    return out, stats


def test_detection_record_fields():
    out, stats = run(["wave-login.com", "example.org"])
    assert stats == {"domains": 2, "detections": 1}
    rec = out[0]
    assert rec["domain"] == "wave-login.com"
    assert rec["brand"] == "Wave"
    assert rec["signals"] == ["exact_token"]
    assert "ts" in rec


def test_duplicates_are_reported_once():
    out, stats = run(["wave-login.com", "wave-login.com", "WAVE-login.com."])
    assert len(out) == 1
    assert stats["domains"] == 3


def test_seen_is_bounded():
    s = Seen(maxsize=2)
    s.add("a.com"); s.add("b.com"); s.add("c.com")
    assert s.add("a.com") is False  # "a.com" a ete oublie
