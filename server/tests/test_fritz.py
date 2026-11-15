import pytest
from fritzconnection.core.exceptions import (
    FritzActionError,
    FritzAuthorizationError,
    FritzLookUpError,
)

from lanot.fritz import FritzPoller

NONE_FIELDS = {
    "link_up": None,
    "wan_connected": None,
    "external_ip": None,
    "uptime_s": None,
    "downstream_kbps": None,
    "upstream_kbps": None,
}


def raising(exc):
    def factory(host, user, password):
        raise exc

    return factory


class FakeConn:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call_action(self, service, action, **kw):
        self.calls.append((service, action))
        r = self.responses.get((service, action))
        if isinstance(r, Exception):
            raise r
        if r is None:
            raise FritzLookUpError(service)
        return r


FULL = {
    ("WANCommonIFC1", "GetCommonLinkProperties"): {
        "NewPhysicalLinkStatus": "Up",
        "NewLayer1DownstreamMaxBitRate": 500_000_000,
        "NewLayer1UpstreamMaxBitRate": 100_000_000,
    },
    ("WANIPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Connected", "NewUptime": 1234},
    ("WANIPConn1", "GetExternalIPAddress"): {"NewExternalIPAddress": "203.0.113.7"},
}


def test_fritz_bad_credentials_never_raises():
    p = FritzPoller("192.168.178.1", "u", "p", connection_factory=raising(FritzAuthorizationError()))
    assert p.poll() == {"ok": False, "error": "FritzBox login failed", **NONE_FIELDS}


@pytest.mark.parametrize("exc", [ConnectionError("x"), TimeoutError(), OSError("no route")])
def test_fritz_unreachable(exc):
    p = FritzPoller("h", "u", "p", connection_factory=raising(exc))
    r = p.poll()
    assert r["ok"] is False and r["error"] == "FritzBox unreachable"


def test_fritz_unreachable_requests_exception():
    import requests

    p = FritzPoller("h", "u", "p", connection_factory=raising(requests.exceptions.ConnectTimeout()))
    assert p.poll()["error"] == "FritzBox unreachable"


def test_fritz_other_error_hides_password():
    p = FritzPoller("h", "u", "test-password-123", connection_factory=raising(ValueError("pw test-password-123")))
    r = p.poll()
    assert r["ok"] is False
    assert r["error"] == "FritzBox query failed: ValueError"
    assert "test-password-123" not in str(r)


def test_fritz_no_credentials():
    called = []
    p = FritzPoller("h", None, None, connection_factory=lambda *a: called.append(a))
    assert p.poll() == {"ok": False, "error": "No FritzBox user configured", **NONE_FIELDS}
    assert not called


def test_fritz_ok_maps_fields():
    conn = FakeConn(FULL)
    r = FritzPoller("h", "u", "p", connection_factory=lambda *a: conn).poll()
    assert r == {
        "ok": True,
        "error": None,
        "link_up": True,
        "wan_connected": True,
        "external_ip": "203.0.113.7",
        "uptime_s": 1234,
        "downstream_kbps": 500_000,
        "upstream_kbps": 100_000,
    }


def test_fritz_ppp_fallback_and_missing_link_service():
    # cable: no WANCommonIFC link data; PPP instead of IP connection
    conn = FakeConn(
        {
            ("WANPPPConn1", "GetStatusInfo"): {"NewConnectionStatus": "Disconnected", "NewUptime": 0},
            ("WANPPPConn1", "GetExternalIPAddress"): {"NewExternalIPAddress": ""},
        }
    )
    r = FritzPoller("h", "u", "p", connection_factory=lambda *a: conn).poll()
    assert r["ok"] is True and r["error"] is None
    assert r["link_up"] is None and r["downstream_kbps"] is None
    assert r["wan_connected"] is False and r["uptime_s"] == 0 and r["external_ip"] is None


def test_fritz_action_error_is_none_not_failure():
    resp = dict(FULL)
    resp[("WANCommonIFC1", "GetCommonLinkProperties")] = FritzActionError("nope")
    r = FritzPoller("h", "u", "p", connection_factory=lambda *a: FakeConn(resp)).poll()
    assert r["ok"] is True and r["link_up"] is None and r["wan_connected"] is True


def test_fritz_auth_error_during_call():
    resp = dict(FULL)
    resp[("WANIPConn1", "GetStatusInfo")] = FritzAuthorizationError()
    r = FritzPoller("h", "u", "p", connection_factory=lambda *a: FakeConn(resp)).poll()
    assert r["error"] == "FritzBox login failed" and r["ok"] is False


def test_event_log_filters_since_and_never_raises():
    import datetime as dt
    from zoneinfo import ZoneInfo

    tz = ZoneInfo("America/New_York")
    since = dt.datetime(2026, 11, 14, 12, 0, 0, tzinfo=tz).timestamp()
    log = "14.11.26 12:30:00 DSL online\n14.11.26 11:00:00 old\ngarbage\n"
    conn = FakeConn({("DeviceInfo1", "GetDeviceLog"): {"NewDeviceLog": log}})
    p = FritzPoller("h", "u", "p", connection_factory=lambda *a: conn, tz="America/New_York")
    assert p.event_log(since) == ["14.11.26 12:30:00 DSL online"]
    q = FritzPoller("h", "u", "p", connection_factory=raising(OSError()))
    assert q.event_log(0) == []
