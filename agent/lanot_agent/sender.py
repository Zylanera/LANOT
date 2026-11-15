"""Deliver reports to the LANOT server; buffer on disk when it is unreachable."""

import logging

import httpx
from pydantic import BaseModel

from .buffer import DiskBuffer

log = logging.getLogger(__name__)

_DROP = {400, 413, 422}


class Sender:
    def __init__(self, url: str, token: str, buffer: DiskBuffer, client: httpx.Client) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.buffer = buffer
        self.client = client

    def _post(self, kind: str, payload: bytes) -> bool:
        """True when the payload is dealt with (delivered or permanently
        rejected), False when it should be retried later."""
        try:
            resp = self.client.post(
                f"{self.url}/api/v1/{kind}",
                content=payload,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            log.warning("server unreachable (%s): %s", kind, exc)
            return False
        if resp.is_success:
            return True
        if resp.status_code in _DROP:
            # The payload itself is refused; retrying can never help.
            log.warning("server rejected %s with %s, dropping: %s", kind, resp.status_code, resp.text[:200])
            return True
        # 401/403/404 (token or routing fixed later), 408, 429, 5xx: retry later.
        log.warning("server returned %s for %s, will retry", resp.status_code, kind)
        return False

    def send(self, kind: str, model: BaseModel) -> None:
        payload = model.model_dump_json().encode()
        # With a backlog, queue behind it: everything goes out in FIFO order via
        # drain(), and a down server is only probed by drain.
        if self.buffer.peek() is not None or not self._post(kind, payload):
            self.buffer.push(kind, payload)

    def drain(self, max_items: int = 200) -> int:
        """Resend buffered items oldest first; stop at the first failure."""
        sent = 0
        while sent < max_items:
            item = self.buffer.peek()
            if item is None:
                break
            id_, kind, payload = item
            if not self._post(kind, payload):
                break
            self.buffer.ack(id_)
            sent += 1
        return sent
