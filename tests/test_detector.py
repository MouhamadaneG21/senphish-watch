from pathlib import Path

import pytest

from src.detector import BrandDetector, levenshtein

BRANDS = [
    {"name": "Wave", "category": "mobile_money", "keywords": ["wave"],
     "official_domains": ["wave.com"]},
    {"name": "Orange Money", "category": "mobile_money",
     "keywords": ["orangemoney", "orange-money", "om"], "official_domains": ["orange.sn"]},
    {"name": "Sonatel", "category": "telecom", "keywords": ["sonatel"],
     "official_domains": ["sonatel.com", "sonatel.sn"]},
    {"name": "Ecobank", "category": "bank", "keywords": ["ecobank"],
     "official_domains": ["ecobank.com"]},
]


@pytest.fixture
def det():
    return BrandDetector(BRANDS)


def names(results):
    return [r.brand for r in results]


def test_levenshtein():
    assert levenshtein("sonatel", "sonate1") == 1
    assert levenshtein("abc", "abc") == 0


def test_exact_token_with_lure(det):
    r = det.check("wave-login.com")
    assert names(r) == ["Wave"]
    assert "exact_token" in r[0].signals
    assert "login" in r[0].lures


def test_official_domain_and_subdomain_ignored(det):
    assert det.check("wave.com") == []
    assert det.check("app.wave.com") == []


def test_official_domain_used_as_subdomain_is_flagged(det):
    assert names(det.check("wave.com.evil-site.net")) == ["Wave"]


def test_contains(det):
    r = det.check("orangemoney-senegal.xyz")
    assert names(r) == ["Orange Money"]
    assert "contains" in r[0].signals


def test_fuzzy_typosquat(det):
    r = det.check("ecobamk.com")
    assert names(r) == ["Ecobank"]
    assert "fuzzy" in r[0].signals


def test_fuzzy_digit_swap(det):
    assert names(det.check("sonate1.com")) == ["Sonatel"]


def test_homoglyph_digit(det):
    r = det.check("w4ve.com")
    assert names(r) == ["Wave"]
    assert "homoglyph" in r[0].signals


def test_homoglyph_vv(det):
    assert names(det.check("vvave-pay.com")) == ["Wave"]


def test_idn_cyrillic_unicode_and_punycode(det):
    unicode_domain = "w\u0430ve-login.com"  # 'a' cyrillique
    assert names(det.check(unicode_domain)) == ["Wave"]
    puny = unicode_domain.encode("idna").decode()
    assert puny.startswith("xn--")
    r = det.check(puny)
    assert names(r) == ["Wave"]
    assert "idn_homoglyph" in r[0].signals


def test_wildcard(det):
    assert names(det.check("*.wave-secure.net")) == ["Wave"]


def test_no_false_positive_on_short_keyword_substring(det):
    assert det.check("waveform.com") == []
    assert det.check("example.com") == []
    assert det.check("hotel-booking.com") == []  # "om" ne doit pas matcher


def test_lures_alone_do_not_trigger(det):
    assert det.check("login-secure-account.com") == []


def test_real_config_loads():
    path = Path(__file__).resolve().parent.parent / "config" / "brands.yml"
    d = BrandDetector.from_file(path)
    assert len(d.brands) >= 7
