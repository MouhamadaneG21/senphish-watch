"""Moteur de detection de domaines imitant des marques (Phase 2)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

import tldextract
import yaml

# Liste des suffixes embarquee : aucun appel reseau.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Mots typiques des pages de phishing (signal secondaire, jamais suffisant seul).
LURE_WORDS = [
    "login", "signin", "verify", "verif", "secure", "update", "account",
    "compte", "connexion", "paiement", "payment", "recharge", "promo",
    "bonus", "gratuit", "support", "otp", "kyc", "wallet", "cashback",
    "remboursement", "facture", "refund", "confirm",
]

# Caracteres qui ressemblent a des lettres latines.
_CONFUSABLES = {
    "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
}


@dataclass
class Detection:
    domain: str
    brand: str
    category: str
    signals: List[str]
    matched: str
    lures: List[str] = field(default_factory=list)


def levenshtein(a: str, b: str) -> int:
    """Distance d'edition entre deux chaines."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def is_official(domain: str, official_domains: List[str]) -> bool:
    return any(domain == od or domain.endswith("." + od) for od in official_domains)


def _decode_idna(text: str) -> str:
    labels = []
    for label in text.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def _fold(text: str, one_as: str) -> str:
    """Remplace les caracteres ambigus par leur lettre latine probable."""
    out = "".join(_CONFUSABLES.get(c, c) for c in text)
    out = out.replace("1", one_as).replace("rn", "m").replace("vv", "w")
    return out


def _tokens(text: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def _match_view(text: str, keywords: List[str]) -> Tuple[Set[str], str]:
    """Cherche les mots-cles d'une marque dans un texte. Retourne (signaux, mot trouve)."""
    tokens = _tokens(text)
    haystack = text.replace(".", "").replace("-", "")
    signals: Set[str] = set()
    matched = ""
    for kw in keywords:
        kw_flat = kw.replace("-", "")
        if kw in tokens:
            signals.add("exact_token")
            matched = matched or kw
        elif len(kw_flat) >= 5 and kw_flat in haystack:
            signals.add("contains")
            matched = matched or kw
        elif len(kw_flat) >= 5:
            max_dist = 1 if len(kw_flat) < 8 else 2
            for tok in tokens:
                if tok != kw_flat and abs(len(tok) - len(kw_flat)) <= 2:
                    if levenshtein(tok, kw_flat) <= max_dist:
                        signals.add("fuzzy")
                        matched = matched or tok
                        break
    return signals, matched


def _find_lures(text: str) -> List[str]:
    tokens = set(_tokens(text))
    haystack = text.replace(".", "").replace("-", "")
    found = []
    for w in LURE_WORDS:
        if (len(w) < 5 and w in tokens) or (len(w) >= 5 and w in haystack):
            found.append(w)
    return found


class BrandDetector:
    def __init__(self, brands: List[Dict]):
        self.brands = brands

    @classmethod
    def from_file(cls, path) -> "BrandDetector":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(data["brands"])

    def check(self, domain: str) -> List[Detection]:
        domain = normalize_domain(domain)
        ext = _EXTRACT(domain)
        if not ext.domain:
            return []
        # On ignore le suffixe (.com, .sn...) : seuls sous-domaines + domaine comptent.
        text = ".".join(p for p in (ext.subdomain, ext.domain) if p)
        decoded = _decode_idna(text)

        results: List[Detection] = []
        for brand in self.brands:
            if is_official(domain, brand.get("official_domains", [])):
                continue
            keywords = [k.lower() for k in brand["keywords"]]

            signals, matched = _match_view(decoded, keywords)
            if not signals:
                # Domaine "deguise" : on teste les versions depliees (0->o, vv->w, 1->l ou i...)
                for one_as in ("l", "i"):
                    folded = _fold(decoded, one_as)
                    if folded == decoded:
                        continue
                    folded_signals, folded_matched = _match_view(folded, keywords)
                    if folded_signals:
                        signals = {"idn_homoglyph" if text != decoded else "homoglyph"}
                        matched = folded_matched
                        break
            if signals:
                results.append(
                    Detection(
                        domain=domain,
                        brand=brand["name"],
                        category=brand["category"],
                        signals=sorted(signals),
                        matched=matched,
                        lures=_find_lures(decoded),
                    )
                )
        return results
