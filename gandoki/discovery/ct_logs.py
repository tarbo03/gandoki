"""Certstream — free, no auth. Noisy; enabled only if the user opts in."""
from __future__ import annotations
import asyncio
import queue as _queue


async def stream_ct_matches(keywords: list[str]):
    """Async generator yielding matching domains from the CT log firehose.

    Requires `pip install certstream`. If certstream is not installed the
    generator exits immediately (no exception) so the orchestrator can
    silently skip a disabled discovery source.
    """
    try:
        import certstream
    except ImportError:
        return

    q: _queue.Queue = _queue.Queue(maxsize=10000)

    def _cb(message, _ctx):
        if message.get("message_type") != "certificate_update":
            return
        leaf = message.get("data", {}).get("leaf_cert", {})
        for d in leaf.get("all_domains", []):
            if any(k in d for k in keywords):
                try:
                    q.put_nowait(d)
                except _queue.Full:
                    pass

    certstream.listen_for_events(_cb)  # starts background thread
    while True:
        try:
            item = await asyncio.to_thread(q.get, True, 30)
        except _queue.Empty:
            continue
        yield item
