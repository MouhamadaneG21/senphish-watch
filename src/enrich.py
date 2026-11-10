"""Enrichissement d'un domaine suspect : age (RDAP) et resolution DNS."""
from __future__ import annotations

import json
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from src.detector import _EXTRACT, normalize_domain

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 8
CACHE_MAX = 10000


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/rdap+json, application/json",
                 "User-Agent": "senphish-watch/0.1 (research)"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_ips(domain: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def rdap_base_for(tld: str, bootstrap: dict) -> Optional[str]:
    """Trouve l'URL du serveur RDAP d'un TLD dans le fichier bootstrap de l'IANA."""
    for tlds, urls in bootstrap.get("services", []):
        if tld in tlds and urls:
            base = urls[0]
            return base if base.endswith("/") else base + "/"
    return None


def parse_rdap(data: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extrait (date d'enregistrement, registrar) d'une reponse RDAP."""
    created = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            created = event.get("eventDate")
            break
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray") or [None, []]
            for item in vcard[1]:
                if len(item) >= 4 and item[0] == "fn":
                    registrar = item[3]
            break
    return created, registrar


def age_days(created: Optional[str], now: Optional[datetime] = None) -> Optional[int]:
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max((now - dt).days, 0)


class Enricher:
    def __init__(self, fetch: Callable[[str], dict] = fetch_json,
                 resolver: Callable[[str], List[str]] = resolve_ips):
        self._fetch = fetch
        self._resolver = resolver
        self._bootstrap: Optional[dict] = None
        self._rdap_cache: Dict[str, dict] = {}

    def _rdap(self, registered: str, tld: str) -> dict:
        if registered in self._rdap_cache:
            return self._rdap_cache[registered]
        result = {"rdap": "unavailable", "created": None, "registrar": None}
        try:
            if self._bootstrap is None:
                self._bootstrap = self._fetch(BOOTSTRAP_URL)
            base = rdap_base_for(tld, self._bootstrap)
            if base:
                created, registrar = parse_rdap(self._fetch(base + "domain/" + registered))
                result = {"rdap": "ok", "created": created, "registrar": registrar}
        except Exception:  # reseau, JSON invalide, limite de debit : on continue sans age
            return result  # echec temporaire : on ne le met pas en cache
        if len(self._rdap_cache) >= CACHE_MAX:
            self._rdap_cache.clear()
        self._rdap_cache[registered] = result
        return result

    def enrich(self, domain: str) -> dict:
        """Bloquant : a lancer dans un thread (run_in_executor)."""
        domain = normalize_domain(domain)
        ext = _EXTRACT(domain)
        registered = ".".join(p for p in (ext.domain, ext.suffix) if p) or domain
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        info = self._rdap(registered, tld)
        ips = self._resolver(domain)
        return {
            "registered_domain": registered,
            "rdap": info["rdap"],
            "created": info["created"],
            "age_days": age_days(info["created"]),
            "registrar": info["registrar"],
            "ips": ips,
            "resolves": bool(ips),
        }
