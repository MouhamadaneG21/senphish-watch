from datetime import datetime, timezone

from src.enrich import Enricher, age_days, parse_rdap, rdap_base_for

BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["sn"], ["https://rdap.nic.sn"]]]}

RDAP = {
    "events": [{"eventAction": "last changed", "eventDate": "2026-11-09T10:00:00Z"},
               {"eventAction": "registration", "eventDate": "2026-11-05T08:30:00Z"}],
    "entities": [{"roles": ["registrar"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                           ["fn", {}, "text", "Exemple Registrar Inc."]]]}],
}


def test_rdap_base_for():
    assert rdap_base_for("com", BOOTSTRAP) == "https://rdap.verisign.com/com/v1/"
    assert rdap_base_for("sn", BOOTSTRAP) == "https://rdap.nic.sn/"
    assert rdap_base_for("xyz", BOOTSTRAP) is None


def test_parse_rdap():
    assert parse_rdap(RDAP) == ("2026-11-05T08:30:00Z", "Exemple Registrar Inc.")
    assert parse_rdap({}) == (None, None)


def test_age_days():
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    assert age_days("2026-11-05T08:30:00Z", now) == 4
    assert age_days(None, now) is None
    assert age_days("pas une date", now) is None


def test_enrich_full_and_cache():
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return BOOTSTRAP if url.endswith("dns.json") else RDAP

    e = Enricher(fetch=fake_fetch, resolver=lambda d: ["203.0.113.7"])
    info = e.enrich("login.wave-pay.com")
    assert info["registered_domain"] == "wave-pay.com"
    assert info["rdap"] == "ok"
    assert info["created"] == "2026-11-05T08:30:00Z"
    assert info["registrar"] == "Exemple Registrar Inc."
    assert info["ips"] == ["203.0.113.7"] and info["resolves"] is True
    assert "https://rdap.verisign.com/com/v1/domain/wave-pay.com" in calls
    n = len(calls)
    e.enrich("autre.wave-pay.com")  # meme domaine enregistre : RDAP en cache
    assert len(calls) == n


def test_enrich_survives_network_failure():
    def boom(url):
        raise OSError("pas de reseau")

    info = Enricher(fetch=boom, resolver=lambda d: []).enrich("wave-pay.com")
    assert info["rdap"] == "unavailable"
    assert info["age_days"] is None and info["resolves"] is False


def test_temporary_failure_is_not_cached():
    state = {"fail": True}

    def flaky(url):
        if state["fail"]:
            raise OSError("limite de debit")
        return BOOTSTRAP if url.endswith("dns.json") else RDAP

    e = Enricher(fetch=flaky, resolver=lambda d: [])
    assert e.enrich("wave-pay.com")["rdap"] == "unavailable"
    state["fail"] = False
    assert e.enrich("wave-pay.com")["rdap"] == "ok"  # nouvel essai reussi
