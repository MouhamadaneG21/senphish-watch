import asyncio
import json

import websockets

URL = "ws://127.0.0.1:8080/domains-only"


async def main():
    async with websockets.connect(URL) as ws:
        async for message in ws:
            for domain in json.loads(message).get("data", []):
                print(domain, flush=True)


asyncio.run(main())
