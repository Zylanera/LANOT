"""FritzBox TR-064 poller (read-only queries). poll() and event_log() never raise."""

import datetime as dt
import logging
from collections.abc import Callable
from zoneinfo import ZoneInfo

from fritzconnection import FritzConnection
from fritzconnection.core.exceptions import (
    ActionError,
    FritzAuthorizationError,
    FritzLookUpError,
    ServiceError,
)

log = logging.getLogger(__name__)

ERR_AUTH = "FritzBox login failed"
ERR_UNREACHABLE = "FritzBox unreachable"
ERR_NO_USER = "No FritzBox user configured"

_FIELDS = ("link_up", "wan_connected", "external_ip", "uptime_s", "downstream_kbps", "upstream_kbps")
_MISSING = (ServiceError, ActionError, FritzLookUpError)


def _default_factory(host, user, password):
    return FritzConnection(address=host, user=user, password=password, timeout=5)


def _result(ok: bool, error: str | None, **fields) -> dict:
    return {"ok": ok, "error": error, **{k: fields.get(k) for k in _FIELDS}}


def _kbps(v) -> int | None:
    return int(v) // 1000 if v is not None else None


class FritzPoller:
    def __init__(self, host, user, password, connection_factory: Callable = _default_factory, tz: str = "UTC"):
        """`tz`: the box's own time zone; its event log has local timestamps."""
        self.host = host
        self.tz = tz
        self.user = user
        self.password = password
        self._factory = connection_factory

    @staticmethod
    def _call(conn, service: str, action: str) -> dict | None:
        """None when the box does not offer this service/action (e.g. no DSL on cable)."""
        try:
            return conn.call_action(service, action)
        except _MISSING:
            return None

    def poll(self) -> dict:
        if not self.user or not self.password:
            return _result(False, ERR_NO_USER)
        try:
            conn = self._factory(self.host, self.user, self.password)
            link = self._call(conn, "WANCommonIFC1", "GetCommonLinkProperties")
            svc = "WANIPConn1"
            status = self._call(conn, svc, "GetStatusInfo")
            if status is None:
                svc = "WANPPPConn1"
                status = self._call(conn, svc, "GetStatusInfo")
            ip = self._call(conn, svc, "GetExternalIPAddress") if status is not None else None
            link, status = link or {}, status or {}
            return _result(
                True,
                None,
                link_up=(link["NewPhysicalLinkStatus"] == "Up") if "NewPhysicalLinkStatus" in link else None,
                wan_connected=(
                    (status["NewConnectionStatus"] == "Connected")
                    if "NewConnectionStatus" in status
                    else None
                ),
                external_ip=((ip or {}).get("NewExternalIPAddress") or None),
                uptime_s=status.get("NewUptime"),
                downstream_kbps=_kbps(link.get("NewLayer1DownstreamMaxBitRate")),
                upstream_kbps=_kbps(link.get("NewLayer1UpstreamMaxBitRate")),
            )
        except FritzAuthorizationError:
            return _result(False, ERR_AUTH)
        except OSError:  # includes ConnectionError, TimeoutError, requests exceptions
            return _result(False, ERR_UNREACHABLE)
        except Exception as e:
            # type name only: messages may carry credentials
            return _result(False, f"FritzBox query failed: {type(e).__name__}")

    def event_log(self, since: float) -> list[str]:
        """Device log lines newer than `since` (epoch seconds); [] on any failure."""
        try:
            conn = self._factory(self.host, self.user, self.password)
            raw = (self._call(conn, "DeviceInfo1", "GetDeviceLog") or {}).get("NewDeviceLog") or ""
        except Exception:
            return []
        tz = ZoneInfo(self.tz)
        out = []
        for line in raw.splitlines():
            try:  # FRITZ!OS writes "14.11.26 12:30:00 <text>" whatever the UI language
                ts = dt.datetime.strptime(line[:17], "%d.%m.%y %H:%M:%S").replace(tzinfo=tz).timestamp()
            except ValueError:
                continue
            if ts >= since:
                out.append(line)
        return out
