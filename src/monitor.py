"""Surveille le flux Certstream et journalise les domaines suspects."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

import websockets

from src.detector import BrandDetector, normalize_domain
from src.enrich import Enricher

URL = os.environ.get("CERTSTREAM_URL", "ws://127.0.0.1:8080/domains-only")
BRANDS_FILE = os.environ.get("BRANDS_FILE", "config/brands.yml")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "data/detections.jsonl")
SEEN_MAX = 200000
STATS_EVERY = 60
ENRICH = os.environ.get("ENRICH", "1") == "1"
ENRICH_CONCURRENCY = 5

log = logging.getLogger("senphish")


class Seen:
    """Memoire des derniers domaines vus (un meme certificat arrive plusieurs fois)."""

    def __init__(self, maxsize: int = SEEN_MAX):
        self.maxsize = maxsize
        self._items = OrderedDict()

    def add(self, domain: str) -> bool:
        """Retourne True si le domaine etait deja vu."""
        if domain in self._items:
            self._items.move_to_end(domain)
            return True
        self._items[domain] = None
        if len(self._items) > self.maxsize:
            self._items.popitem(last=False)
        return False


def handle_domains(domains, detector, seen, emit, stats):
    """Passe chaque nouveau domaine dans le moteur et emet un enregistrement par detection."""
    for domain in domains:
        stats["domains"] += 1
        domain = normalize_domain(domain)
        if seen.add(domain):
            continue
        for det in detector.check(domain):
            stats["detections"] += 1
            emit({
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "domain": det.domain,
                "brand": det.brand,
                "category": det.category,
                "signals": det.signals,
                "matched": det.matched,
                "lures": det.lures,
            })


async def report_stats(stats):
    while True:
        await asyncio.sleep(STATS_EVERY)
        log.info("stats: %d domaines analyses, %d detections",
                 stats["domains"], stats["detections"])


async def run():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    detector = BrandDetector.from_file(BRANDS_FILE)
    seen = Seen()
    stats = {"domains": 0, "detections": 0}
    Path(OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)

    enricher = Enricher()
    sem = asyncio.Semaphore(ENRICH_CONCURRENCY)
    loop = asyncio.get_running_loop()

    with open(OUTPUT_FILE, "a", encoding="utf-8") as out:
        def write(record):
            line = json.dumps(record, ensure_ascii=False)
            out.write(line + "\n")
            out.flush()
            print(line, flush=True)

        async def enrich_and_write(record):
            if ENRICH:
                try:
                    async with sem:
                        record["enrichment"] = await loop.run_in_executor(
                            None, enricher.enrich, record["domain"])
                except Exception as exc:  # on ecrit quand meme la detection brute
                    log.warning("enrichissement impossible pour %s (%s)", record["domain"], exc)
            write(record)

        def emit(record):
            asyncio.ensure_future(enrich_and_write(record))

        asyncio.ensure_future(report_stats(stats))
        backoff = 1
        while True:
            try:
                async with websockets.connect(URL) as ws:
                    log.info("connecte a %s", URL)
                    backoff = 1
                    async for message in ws:
                        data = json.loads(message).get("data", [])
                        handle_domains(data, detector, seen, emit, stats)
            except (OSError, websockets.exceptions.WebSocketException) as exc:
                log.warning("connexion perdue (%s), nouvel essai dans %ds", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    asyncio.run(run())
