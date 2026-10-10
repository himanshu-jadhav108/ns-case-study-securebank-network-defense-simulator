"""Defensive control building blocks (explainable, inspectable rule engines).

IMPORTANT LABELS
- Firewall here is an APPLICATION-LAYER allow/deny policy, not a network firewall.
- IDS here is a handful of explicit rules, not a production IDS.
- IPS here blocks matching requests inside the dummy service/simulator only.
- Segmentation here is a logical zone-to-zone policy enforced by code.
- The same building blocks are used by the Cloud simulator and the local dummy service.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .schemas import ControlConfig  # re-exported for convenience

__all__ = [
    "ControlConfig", "FirewallRule", "FirewallDecision", "Firewall", "DEFAULT_RULES",
    "Segmentation", "ZONES", "ALLOWED_ZONE_PATHS", "RateLimiter", "Alert", "IDS", "IPS",
    "ArpGuard", "TRUSTED_ARP", "detect_arp_conflicts", "AccessControl",
    "sign_message", "verify_message", "load_demo_key", "validate_account_id",
    "validate_transfer",
]

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# --------------------------------------------------------------------------
# Firewall (application-layer rule engine)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FirewallRule:
    rule_id: str
    action: str       # "allow" | "deny"
    src_zone: str     # zone name or "*"
    dst_zone: str
    path: str         # exact path or "*"
    description: str


@dataclass(frozen=True)
class FirewallDecision:
    allowed: bool
    rule_id: str
    reason: str


DEFAULT_RULES: tuple[FirewallRule, ...] = (
    FirewallRule("FW-01", "allow", "internet", "dmz", "/health", "Public health check"),
    FirewallRule("FW-02", "allow", "internet", "dmz", "/balance", "Customer balance lookup (token still required)"),
    FirewallRule("FW-03", "allow", "internet", "dmz", "/transfer-simulated", "Simulated transfer endpoint"),
    FirewallRule("FW-04", "allow", "dmz", "db-zone", "*", "App tier may reach the data tier"),
    FirewallRule("FW-05", "deny", "internet", "db-zone", "*", "Internet may never reach the data tier directly"),
)


class Firewall:
    """First-match rule engine with default-deny. Rules are plain data and inspectable."""

    def __init__(self, rules: Iterable[FirewallRule] | None = None, default_action: str = "deny"):
        self.rules = tuple(rules) if rules is not None else DEFAULT_RULES
        self.default_action = default_action

    def evaluate(self, src_zone: str, dst_zone: str, path: str) -> FirewallDecision:
        for r in self.rules:
            if (r.src_zone in ("*", src_zone) and r.dst_zone in ("*", dst_zone)
                    and r.path in ("*", path)):
                return FirewallDecision(r.action == "allow", r.rule_id, r.description)
        allowed = self.default_action == "allow"
        return FirewallDecision(allowed, "FW-DEFAULT", f"No rule matched; default {self.default_action}")


# --------------------------------------------------------------------------
# Segmentation (logical zones + enforced access paths)
# --------------------------------------------------------------------------

ZONES = ("internet", "user-lan", "dmz", "db-zone")
ALLOWED_ZONE_PATHS = frozenset({
    ("internet", "dmz"),
    ("user-lan", "dmz"),
    ("dmz", "db-zone"),
})


class Segmentation:
    """Zone policy. Traffic inside a zone is allowed; between zones only listed paths."""

    def __init__(self, allowed: frozenset = ALLOWED_ZONE_PATHS):
        self.allowed = allowed

    def permits(self, src_zone: str, dst_zone: str) -> bool:
        return src_zone == dst_zone or (src_zone, dst_zone) in self.allowed


# --------------------------------------------------------------------------
# Rate limiter (fixed window, caller supplies the clock => deterministic)
# --------------------------------------------------------------------------


class RateLimiter:
    def __init__(self, limit: int, window: float = 1.0):
        self.limit = int(limit)
        self.window = float(window)
        self._state: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str, now: float) -> bool:
        with self._lock:
            start, count = self._state.get(source, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            count += 1
            self._state[source] = (start, count)
            return count <= self.limit


# --------------------------------------------------------------------------
# IDS / IPS
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Alert:
    signature: str
    source: str
    detail: str
    tick: int


class IDS:
    """Rule-based detector. Signatures:
    RATE_EXCEEDED, REPEATED_FAILURES, ARP_MAPPING_CONFLICT, INTEGRITY_FAILURE.
    Limited by design: fixed thresholds, no learning, no payload inspection."""

    def __init__(self, rate_threshold: int = 30, failed_threshold: int = 5, failed_window: int = 10):
        self.rate_threshold = rate_threshold
        self.failed_threshold = failed_threshold
        self.failed_window = failed_window
        self._rate: dict[tuple[str, int], int] = defaultdict(int)
        self._rate_alerted: set[tuple[str, int]] = set()
        self._failed: dict[str, list[int]] = defaultdict(list)
        self._arp_seen: dict[str, set[str]] = {}
        self._arp_conflicts: set[tuple[str, str]] = set()
        self._lock = threading.Lock()
        self.alerts: list[Alert] = []

    def _emit(self, alert: Alert) -> Alert:
        self.alerts.append(alert)
        return alert

    def observe_request(self, source: str, tick: int) -> Alert | None:
        with self._lock:
            key = (source, tick)
            self._rate[key] += 1
            if self._rate[key] > self.rate_threshold and key not in self._rate_alerted:
                self._rate_alerted.add(key)
                return self._emit(Alert("RATE_EXCEEDED", source,
                                        f">{self.rate_threshold} requests/tick from {source}", tick))
            return None

    def observe_failed(self, source: str, tick: int) -> Alert | None:
        with self._lock:
            hist = [t for t in self._failed[source] if tick - t < self.failed_window]
            hist.append(tick)
            self._failed[source] = hist
            if len(hist) >= self.failed_threshold:
                self._failed[source] = []
                return self._emit(Alert("REPEATED_FAILURES", source,
                                        f"{self.failed_threshold} failed requests within {self.failed_window} ticks", tick))
            return None

    def observe_arp(self, ip: str, mac: str, trusted: dict[str, str] | None, tick: int = 0,
                    ) -> tuple[bool, Alert | None]:
        """Return (is_conflict, new_alert_or_None). The first conflicting (ip, mac) pair alerts once."""
        mac = mac.lower()
        with self._lock:
            seen = self._arp_seen.setdefault(ip, set())
            if trusted and ip in trusted and not seen:
                seen.add(trusted[ip].lower())
            if not seen:
                seen.add(mac)
                return False, None
            if mac in seen and (ip, mac) not in self._arp_conflicts:
                return False, None
            conflict_key = (ip, mac)
            if conflict_key in self._arp_conflicts:
                return True, None
            self._arp_conflicts.add(conflict_key)
            seen.add(mac)
            return True, self._emit(Alert("ARP_MAPPING_CONFLICT", mac,
                                          f"{ip} previously bound to {sorted(seen - {mac})}, now claimed by {mac}", tick))

    def observe_integrity_failure(self, source: str, tick: int) -> Alert:
        with self._lock:
            return self._emit(Alert("INTEGRITY_FAILURE", source, "HMAC verification failed", tick))


class IPS:
    """Blocks sources after a policy trigger. Time is supplied by the caller."""

    def __init__(self, default_duration: float = float("inf")):
        self.default_duration = default_duration
        self._until: dict[str, float] = {}
        self._lock = threading.Lock()
        self.blocks: list[tuple[str, float, str]] = []

    def block(self, source: str, now: float, reason: str, duration: float | None = None) -> None:
        d = self.default_duration if duration is None else duration
        with self._lock:
            self._until[source] = now + d
            self.blocks.append((source, now, reason))

    def is_blocked(self, source: str, now: float) -> bool:
        with self._lock:
            return self._until.get(source, -1.0) > now


# --------------------------------------------------------------------------
# ARP helpers (synthetic ARP tables only; nothing touches a real network)
# --------------------------------------------------------------------------

TRUSTED_ARP = {"10.0.0.1": "aa:bb:cc:00:00:01"}  # synthetic gateway binding


class ArpGuard:
    """Accept an ARP binding only if it matches the trusted table (static-entry / DAI-like)."""

    def __init__(self, trusted: dict[str, str] | None = None):
        self.trusted = {k: v.lower() for k, v in (trusted or TRUSTED_ARP).items()}

    def accept(self, ip: str, mac: str) -> bool:
        t = self.trusted.get(ip)
        return t is None or t == mac.lower()


def detect_arp_conflicts(observations: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """Return {ip: [macs]} for every IP seen with more than one MAC address."""
    seen: dict[str, list[str]] = {}
    for ip, mac in observations:
        macs = seen.setdefault(ip, [])
        if mac.lower() not in macs:
            macs.append(mac.lower())
    return {ip: macs for ip, macs in seen.items() if len(macs) > 1}


# --------------------------------------------------------------------------
# Access control over FICTIONAL accounts
# --------------------------------------------------------------------------


class AccessControl:
    def __init__(self, accounts_path: Path | None = None):
        path = accounts_path or (DATA_DIR / "dummy_accounts.json")
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self.accounts = {a["account_id"]: a for a in raw["accounts"]}
        self._by_token = {a["token"]: a["account_id"] for a in raw["accounts"]}

    def authenticate(self, token: str | None) -> str | None:
        return self._by_token.get(token) if token else None

    def request_balance(self, token: str | None, account_id: str, enforce: bool = True):
        """Return (allowed, reason, data). With enforce=False the check is skipped (no control)."""
        acct = self.accounts.get(account_id)
        if acct is None:
            return False, "unknown account", None
        if not enforce:
            return True, "no access control (baseline)", {"account_id": account_id, "balance": acct["balance"]}
        who = self.authenticate(token)
        if who is None:
            return False, "authentication failed", None
        if who != account_id:
            return False, "authorisation failed (not the account owner)", None
        return True, "owner authenticated", {"account_id": account_id, "balance": acct["balance"]}


# --------------------------------------------------------------------------
# Integrity: HMAC-SHA256 with a LOCAL DEMONSTRATION key
# --------------------------------------------------------------------------

_FALLBACK_KEY = b"classroom-demo-key-NOT-A-SECRET-do-not-reuse"


def load_demo_key() -> bytes:
    """Demonstration key stored in the repo on purpose. NOT a secret; a real system would
    use a KMS/HSM, per-session keys, rotation and TLS. Never reuse this key anywhere."""
    p = DATA_DIR / "demo_hmac_key.txt"
    try:
        return p.read_text(encoding="utf-8").strip().encode() or _FALLBACK_KEY
    except OSError:
        return _FALLBACK_KEY


def _canonical(message: dict) -> bytes:
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode()


def sign_message(message: dict, key: bytes | None = None) -> str:
    return hmac.new(key or load_demo_key(), _canonical(message), hashlib.sha256).hexdigest()


def verify_message(message: dict, mac: str, key: bytes | None = None) -> bool:
    return hmac.compare_digest(sign_message(message, key), str(mac))


# --------------------------------------------------------------------------
# Input validation (used by the local dummy service)
# --------------------------------------------------------------------------

_ACCOUNT_RE = re.compile(r"^ACC-\d{4}$")
_MEMO_RE = re.compile(r"^[A-Za-z0-9 .,_-]{0,80}$")


def validate_account_id(value) -> bool:
    return isinstance(value, str) and bool(_ACCOUNT_RE.match(value))


def validate_transfer(payload) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "body must be a JSON object"
    for k in ("from", "to", "amount", "memo"):
        if k not in payload:
            return False, f"missing field: {k}"
    if not validate_account_id(payload["from"]) or not validate_account_id(payload["to"]):
        return False, "invalid account id format"
    if payload["from"] == payload["to"]:
        return False, "from and to must differ"
    amt = payload["amount"]
    if isinstance(amt, bool) or not isinstance(amt, (int, float)) or not (0 < amt <= 1000):
        return False, "amount must be a number in (0, 1000]"
    if not isinstance(payload["memo"], str) or not _MEMO_RE.match(payload["memo"]):
        return False, "memo must be <=80 chars of letters, digits and . , _ - space"
    return True, "ok"
