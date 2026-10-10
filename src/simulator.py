"""Deterministic, bounded SIMULATION of ARP spoofing, MITM and DDoS-style disruption.

Nothing here touches a network. There are no sockets, no packet crafting and no
traffic generation: attack "mechanics" are plain Python state transitions over
synthetic data. Every result is labelled SIMULATED. With a fixed seed the output
is identical on every run.
"""
from __future__ import annotations

import random
from collections import Counter, deque

from .controls import (AccessControl, ArpGuard, Firewall, IDS, IPS, RateLimiter,
                       Segmentation, TRUSTED_ARP, sign_message, verify_message)
from .metrics import OUTCOME_LAYER, summarize_requests
from .schemas import (ControlConfig, Event, MODE_SIM, PHASE_BASELINE, PHASE_CONTROLS,
                      RunResult, SCENARIOS)

# ---- hard safety caps: no run can grow without bound -----------------------
MAX_TICKS = 60
MAX_REQUESTS = 20_000
MAX_BOTS = 50
MAX_MESSAGES = 500
MAX_LEGIT_CLIENTS = 50


def _clamp(value, lo, hi):
    return max(lo, min(hi, int(value)))


# ============================================================================
# DDoS-style service disruption (simulated workload against a simulated service)
# ============================================================================

BOT_TARGETS = (  # (dst_zone, path, weight)
    ("dmz", "/balance", 70),
    ("dmz", "/transfer-simulated", 10),
    ("dmz", "/admin", 10),
    ("db-zone", "/db-query", 10),
)
LEGIT_PATHS = ("/balance", "/balance", "/health", "/transfer-simulated")


def run_ddos(controls: ControlConfig | None = None, seed: int = 42, ticks: int = 20,
             legit_clients: int = 8, legit_rate: int = 2, bots: int = 5, bot_rate: int = 40,
             attack_start: int = 5, attack_end: int = 15, attack: bool = True,
             capacity: int = 60, queue_limit: int = 120, timeout_ticks: int = 3,
             base_latency_ms: float = 20.0, phase: str = PHASE_CONTROLS) -> RunResult:
    """1 tick = 1 simulated second. The simulated service handles `capacity` requests per
    tick, queues up to `queue_limit` and abandons requests waiting more than `timeout_ticks`.
    Control pipeline (in order): segmentation -> firewall -> IPS blocklist -> IDS observe ->
    rate limit -> access control -> service queue. Rejected requests cost no service capacity
    (a simplification, listed in `assumptions`)."""
    controls = controls or ControlConfig()
    rng = random.Random(seed)

    ticks = _clamp(ticks, 1, MAX_TICKS)
    legit_clients = _clamp(legit_clients, 1, MAX_LEGIT_CLIENTS)
    legit_rate = _clamp(legit_rate, 1, 20)
    bots = _clamp(bots, 0, MAX_BOTS)
    bot_rate = _clamp(bot_rate, 1, 10 ** 9)
    capacity = _clamp(capacity, 1, 10_000)
    queue_limit = _clamp(queue_limit, 1, 10_000)
    timeout_ticks = _clamp(timeout_ticks, 0, 20)
    attack_start = _clamp(attack_start, 0, ticks)
    attack_end = _clamp(attack_end, attack_start, ticks)

    cap_applied = False
    max_legit = MAX_REQUESTS // 2
    if ticks * legit_clients * legit_rate > max_legit:
        legit_rate = max(1, max_legit // (ticks * legit_clients))
        cap_applied = True
    legit_total = ticks * legit_clients * legit_rate
    attack_ticks = (attack_end - attack_start) if attack else 0
    if attack and bots and attack_ticks:
        max_rate = max(1, (MAX_REQUESTS - legit_total) // (bots * attack_ticks))
        if bot_rate > max_rate:
            bot_rate, cap_applied = max_rate, True

    fw, seg = Firewall(), Segmentation()
    limiter = RateLimiter(controls.rate_limit_per_tick, window=1.0)
    ids = IDS(controls.ids_rate_threshold, controls.ids_failed_threshold)
    ips = IPS()
    acl = AccessControl()
    tokens = [a["token"] for a in acl.accounts.values()]

    events: list[Event] = []
    records: list[dict] = []
    queue: deque = deque()
    ids_alerts = 0

    def ev(tick, layer, action, source, detail):
        events.append(Event(tick, layer, action, source, detail, "ddos", phase, MODE_SIM))

    if attack and bots and attack_ticks:
        ev(attack_start, "scenario", "info", "BOT-*",
           f"SIMULATED burst begins: {bots} synthetic sources x {bot_rate} req/tick")
        ev(attack_end, "scenario", "info", "BOT-*", "SIMULATED burst ends")

    weights = [w for _, _, w in BOT_TARGETS]

    for tick in range(ticks):
        arrivals = []
        for c in range(legit_clients):
            for _ in range(legit_rate):
                arrivals.append({"tick": tick, "src": f"CLIENT-{c}", "legit": True, "zone": "internet",
                                 "dst": "dmz", "path": rng.choice(LEGIT_PATHS),
                                 "token": tokens[c % len(tokens)], "outcome": None, "latency_ms": None})
        if attack and bots and attack_start <= tick < attack_end:
            for b in range(bots):
                for _ in range(bot_rate):
                    dst, path, _w = rng.choices(BOT_TARGETS, weights=weights)[0]
                    arrivals.append({"tick": tick, "src": f"BOT-{b}", "legit": False, "zone": "internet",
                                     "dst": dst, "path": path, "token": None,
                                     "outcome": None, "latency_ms": None})
        rng.shuffle(arrivals)
        counts: Counter = Counter()

        for r in arrivals:
            src = r["src"]
            if controls.segmentation and not seg.permits(r["zone"], r["dst"]):
                r["outcome"] = "denied_segmentation"
            elif controls.firewall and not fw.evaluate(r["zone"], r["dst"], r["path"]).allowed:
                r["outcome"] = "denied_firewall"
            elif controls.ips and ips.is_blocked(src, tick):
                r["outcome"] = "blocked_ips"
            else:
                if controls.ids:
                    a = ids.observe_request(src, tick)
                    if a:
                        ids_alerts += 1
                        ev(tick, "ids", "detect", src, f"{a.signature}: {a.detail}")
                        if controls.ips:
                            ips.block(src, tick, a.signature)
                            ev(tick, "ips", "block", src, f"Source blocked after {a.signature}")
                if controls.rate_limit and not limiter.allow(src, tick):
                    r["outcome"] = "rejected_rate_limit"
                elif controls.access_control and r["token"] is None:
                    r["outcome"] = "rejected_auth"
                    if controls.ids:
                        a = ids.observe_failed(src, tick)
                        if a:
                            ids_alerts += 1
                            ev(tick, "ids", "detect", src, f"{a.signature}: {a.detail}")
                            if controls.ips:
                                ips.block(src, tick, a.signature)
                                ev(tick, "ips", "block", src, f"Source blocked after {a.signature}")
                elif len(queue) >= queue_limit:
                    r["outcome"] = "dropped_overload"
                else:
                    r["outcome"] = "queued"
                    queue.append((tick, r))
            records.append(r)
            if r["outcome"] not in ("queued",):
                counts[r["outcome"]] += 1

        # --- service side: expire stale requests, then serve up to capacity ----
        while queue and tick - queue[0][0] > timeout_ticks:
            _, old = queue.popleft()
            old["outcome"] = "timeout"
            counts["timeout"] += 1
        util = min(len(queue), capacity) / capacity
        served = 0
        while queue and served < capacity:
            at, req = queue.popleft()
            req["outcome"] = "served"
            req["latency_ms"] = round(base_latency_ms * (1 + util) + (tick - at) * 1000.0
                                      + rng.uniform(0, 10), 2)
            served += 1

        for outcome, n in sorted(counts.items()):
            layer = OUTCOME_LAYER.get(outcome, "service")
            action = "deny" if outcome.startswith(("denied", "rejected")) else \
                     "block" if outcome == "blocked_ips" else "info"
            if outcome in ("dropped_overload", "timeout"):
                action = "compromise"
            ev(tick, layer, action, "multiple", f"{n} request(s) -> {outcome}")

    while queue:  # anything still queued at the end never completed
        _, old = queue.popleft()
        old["outcome"] = "timeout"

    m = summarize_requests(records, ticks)
    m.update({
        "detection_count": ids_alerts,
        "block_count": m["count_blocked_ips"],
        "sources_blocked": len(ips.blocks),
        "ticks_simulated": ticks,
        "request_cap_applied": cap_applied,
        "service_capacity_per_tick": capacity,
    })
    status = ("AVAILABLE" if (m["legit_success_rate_pct"] or 0) >= 95 else
              "DEGRADED" if (m["legit_success_rate_pct"] or 0) >= 60 else "UNAVAILABLE")
    m["simulated_service_status"] = status

    return RunResult(
        "ddos", phase, seed, controls.to_dict(), m, events, records,
        assumptions=[
            f"{legit_clients} legitimate clients x {legit_rate} req/tick; {bots} synthetic bot sources x {bot_rate} req/tick during ticks {attack_start}-{attack_end}.",
            f"Simulated service: capacity {capacity}/tick, queue {queue_limit}, timeout {timeout_ticks} ticks.",
            "Rejected requests cost no service capacity (simplification; real filtering also consumes resources).",
            "Source identity is a synthetic label; a real attacker can spoof or distribute sources.",
            f"Safety caps: <= {MAX_TICKS} ticks, <= {MAX_REQUESTS} requests per run.",
        ],
        residual_risk=[
            "Volumetric attacks that saturate the network link upstream of the service are not stopped by in-app controls.",
            "Per-source rate limits are weak against many distinct sources (distributed attacks).",
            "Fixed IDS thresholds can be evaded by low-and-slow traffic or cause false positives on flash crowds.",
        ])


# ============================================================================
# ARP spoofing (synthetic ARP caches; no packets are ever created)
# ============================================================================

ARP_HOSTS = (  # (name, ip, zone)
    ("ws-a", "10.0.0.20", "user-lan"),
    ("ws-b", "10.0.0.21", "user-lan"),
    ("app-srv", "10.0.1.10", "dmz"),
    ("db-srv", "10.0.2.10", "db-zone"),
)
ARP_ATTACKER_MAC = "de:ad:be:ef:00:66"
ARP_ATTACKER_ZONE = "user-lan"
GATEWAY_IP = "10.0.0.1"


def run_arp_spoofing(controls: ControlConfig | None = None, seed: int = 42, ticks: int = 10,
                     attack_start: int = 2, messages_per_tick: int = 3,
                     phase: str = PHASE_CONTROLS) -> RunResult:
    """A synthetic attacker repeatedly sends forged 'gateway is at <attacker MAC>' ARP replies
    to synthetic hosts. Poisoned caches divert that host's messages to the attacker.
    Pipeline per forged frame: segmentation -> IDS sensor -> ARP guard -> IPS -> cache update.
    Without segmentation the network is modelled as one flat broadcast domain."""
    controls = controls or ControlConfig()
    rng = random.Random(seed)  # reserved for deterministic extensions; ordering is fixed
    _ = rng
    ticks = _clamp(ticks, 1, MAX_TICKS)
    attack_start = _clamp(attack_start, 0, ticks)
    messages_per_tick = _clamp(messages_per_tick, 1, 20)

    ids = IDS(controls.ids_rate_threshold, controls.ids_failed_threshold)
    ips = IPS()
    guard = ArpGuard()
    caches = {h[0]: {GATEWAY_IP: TRUSTED_ARP[GATEWAY_IP]} for h in ARP_HOSTS}
    events: list[Event] = []
    records: list[dict] = []
    stats = Counter()
    ids_alerts = 0

    def ev(tick, layer, action, source, detail):
        events.append(Event(tick, layer, action, source, detail, "arp_spoofing", phase, MODE_SIM))

    ev(attack_start, "scenario", "info", ARP_ATTACKER_MAC,
       f"SIMULATED attacker (zone {ARP_ATTACKER_ZONE}) starts forging ARP replies for {GATEWAY_IP}")

    for tick in range(ticks):
        if tick >= attack_start:
            for name, ip, zone in ARP_HOSTS:
                stats["forged_frames_sent"] += 1
                if controls.segmentation and zone != ARP_ATTACKER_ZONE:
                    stats["frames_dropped_segmentation"] += 1
                    ev(tick, "segmentation", "deny", ARP_ATTACKER_MAC,
                       f"Frame to {name} ({zone}) never crosses the zone boundary")
                    continue
                conflict = False
                if controls.ids:
                    conflict, alert = ids.observe_arp(GATEWAY_IP, ARP_ATTACKER_MAC, TRUSTED_ARP, tick)
                    if alert:
                        ids_alerts += 1
                        ev(tick, "ids", "detect", ARP_ATTACKER_MAC, f"{alert.signature}: {alert.detail}")
                if controls.arp_protection and not guard.accept(GATEWAY_IP, ARP_ATTACKER_MAC):
                    stats["frames_dropped_arp_guard"] += 1
                    ev(tick, "arp_protection", "deny", ARP_ATTACKER_MAC,
                       f"Binding {GATEWAY_IP}->{ARP_ATTACKER_MAC} rejected for {name} (trusted table mismatch)")
                    continue
                if controls.ips and conflict:
                    stats["frames_blocked_ips"] += 1
                    if not ips.blocks:
                        ips.block(ARP_ATTACKER_MAC, tick, "ARP_MAPPING_CONFLICT")
                    ev(tick, "ips", "block", ARP_ATTACKER_MAC,
                       f"Conflicting ARP reply to {name} dropped")
                    continue
                if caches[name][GATEWAY_IP] != ARP_ATTACKER_MAC:
                    ev(tick, "host", "compromise", name,
                       f"ARP cache poisoned: {GATEWAY_IP} now maps to {ARP_ATTACKER_MAC}")
                caches[name][GATEWAY_IP] = ARP_ATTACKER_MAC
        for name, _ip, _zone in ARP_HOSTS:
            for _ in range(messages_per_tick):
                diverted = caches[name][GATEWAY_IP] == ARP_ATTACKER_MAC
                stats["messages_diverted" if diverted else "messages_delivered"] += 1
                records.append({"tick": tick, "host": name,
                                "outcome": "diverted" if diverted else "delivered"})

    poisoned = sum(1 for c in caches.values() if c[GATEWAY_IP] == ARP_ATTACKER_MAC)
    total_msgs = stats["messages_diverted"] + stats["messages_delivered"]
    m = {
        "hosts_total": len(ARP_HOSTS),
        "forged_frames_sent": stats["forged_frames_sent"],
        "frames_dropped_segmentation": stats["frames_dropped_segmentation"],
        "frames_dropped_arp_guard": stats["frames_dropped_arp_guard"],
        "frames_blocked_ips": stats["frames_blocked_ips"],
        "caches_poisoned": poisoned,
        "messages_total": total_msgs,
        "messages_delivered": stats["messages_delivered"],
        "messages_diverted": stats["messages_diverted"],
        "diversion_rate_pct": round(100.0 * stats["messages_diverted"] / total_msgs, 2) if total_msgs else 0.0,
        "detection_count": ids_alerts,
        "block_count": stats["frames_blocked_ips"],
        "mitm_position_achieved": poisoned > 0,
    }
    return RunResult(
        "arp_spoofing", phase, seed, controls.to_dict(), m, events, records,
        assumptions=[
            "Synthetic hosts, synthetic MACs; no real ARP traffic exists anywhere in this run.",
            f"Attacker sits in zone '{ARP_ATTACKER_ZONE}'. Without segmentation all hosts share one flat broadcast domain.",
            "Hosts accept unsolicited ARP replies and never expire entries (worst case for the baseline).",
            "IDS is a sensor that sees every frame; with IDS only (no IPS/guard) it detects but does not prevent.",
        ],
        residual_risk=[
            "Hosts in the attacker's own zone remain exposed unless ARP protection (DAI/static entries) is enforced.",
            "IDS alone detects but does not stop poisoning; detection depends on a trusted baseline table.",
            "Static/trusted bindings are hard to maintain at scale and need switch support in real networks.",
            "Segmentation limits blast radius; it does not authenticate hosts inside a zone.",
        ],
        details={"final_arp_caches": {k: dict(v) for k, v in caches.items()},
                 "trusted_binding": dict(TRUSTED_ARP), "attacker_mac": ARP_ATTACKER_MAC})


# ============================================================================
# MITM (dummy messages; attacker is a function acting on dictionaries)
# ============================================================================

def run_mitm(controls: ControlConfig | None = None, seed: int = 42, messages: int = 20,
             tamper_probability: float = 0.4, phase: str = PHASE_CONTROLS) -> RunResult:
    """Dummy transfer messages pass through a simulated on-path attacker. Without ARP
    protection the attacker is on the path (e.g. via the ARP scenario). Controls:
    encryption (SIMULATED: attacker cannot read), HMAC (tampering detected), IDS/IPS."""
    controls = controls or ControlConfig()
    rng = random.Random(seed)
    messages = _clamp(messages, 1, MAX_MESSAGES)
    tamper_probability = max(0.0, min(1.0, float(tamper_probability)))
    ids = IDS(controls.ids_rate_threshold, controls.ids_failed_threshold)
    events: list[Event] = []
    records: list[dict] = []
    stats = Counter()
    ids_alerts = 0

    def ev(tick, layer, action, source, detail):
        events.append(Event(tick, layer, action, source, detail, "mitm", phase, MODE_SIM))

    on_path = not controls.arp_protection
    if on_path:
        ev(0, "scenario", "info", "MITM-SIM", "SIMULATED attacker is on the client->server path")
    else:
        ev(0, "arp_protection", "deny", "MITM-SIM",
           "Poisoning attempt rejected: attacker never gains an on-path position (layer 1 stops the scenario)")

    for i in range(messages):
        msg = {"from": "ACC-1001", "to": "ACC-1002", "amount": rng.randint(10, 500),
               "memo": f"demo-{i:03d}"}
        mac = sign_message(msg) if controls.hmac_integrity else None
        wire = dict(msg)
        tampered = read = False
        if on_path:
            if not controls.encryption:
                read = True
                stats["read_by_attacker"] += 1
                ev(i, "attacker", "compromise", "MITM-SIM", f"Plaintext read: {msg['memo']} amount={msg['amount']}")
            if rng.random() < tamper_probability:
                tampered = True
                stats["tampered"] += 1
                wire["amount"] = msg["amount"] * 10 + 1
        outcome = "accepted_original"
        if tampered:
            if controls.hmac_integrity and not verify_message(wire, mac):
                stats["tampered_detected"] += 1
                outcome = "rejected_tampered"
                if controls.ids:
                    a = ids.observe_integrity_failure("MITM-SIM", i)
                    ids_alerts += 1
                    ev(i, "ids", "detect", "MITM-SIM", f"{a.signature}: {msg['memo']}")
                if controls.ips:
                    stats["blocked_by_ips"] += 1
                    ev(i, "ips", "block", "MITM-SIM", f"Tampered message {msg['memo']} quarantined")
                else:
                    ev(i, "hmac_integrity", "deny", "MITM-SIM", f"Tampered message {msg['memo']} rejected")
            else:
                stats["tampered_accepted"] += 1
                outcome = "accepted_TAMPERED"
                ev(i, "service", "compromise", "MITM-SIM",
                   f"Server accepted modified amount {wire['amount']} (original {msg['amount']})")
        else:
            stats["accepted_original"] += 1
        records.append({"msg": msg["memo"], "read_by_attacker": read, "tampered": tampered, "outcome": outcome})

    tampered_n = stats["tampered"]
    m = {
        "messages_total": messages,
        "attacker_on_path": on_path,
        "messages_read_by_attacker": stats["read_by_attacker"],
        "confidentiality_exposure_pct": round(100.0 * stats["read_by_attacker"] / messages, 2),
        "messages_tampered": tampered_n,
        "tampered_accepted": stats["tampered_accepted"],
        "tampered_detected": stats["tampered_detected"],
        "integrity_check_outcome": ("N/A (no tampering occurred)" if tampered_n == 0 else
                                    "PASS" if stats["tampered_accepted"] == 0 else "FAIL"),
        "detection_count": ids_alerts,
        "block_count": stats["blocked_by_ips"],
    }
    return RunResult(
        "mitm", phase, seed, controls.to_dict(), m, events, records,
        assumptions=[
            "Messages are fictional dictionaries; the 'attacker' is a function, not a network tool.",
            "Encryption is SIMULATED as a flag (attacker cannot read). It is confidentiality-only here; real TLS also gives integrity.",
            "HMAC uses a local demonstration key stored in the repo; this is NOT real key management.",
            f"Tamper probability {tamper_probability:.2f}; the on-path position is assumed unless ARP protection is on.",
        ],
        residual_risk=[
            "HMAC with a shared key proves tampering, not who sent a message; a compromised key breaks it.",
            "Replay of valid signed messages is not prevented here (needs nonces/timestamps).",
            "Traffic metadata (sizes, timing, endpoints) remains visible to an on-path attacker.",
            "Real deployments need TLS with certificate validation plus proper key management.",
        ])


# ============================================================================
# Orchestration
# ============================================================================

_RUNNERS = {"arp_spoofing": run_arp_spoofing, "mitm": run_mitm, "ddos": run_ddos}


def run_scenario(name: str, controls: ControlConfig | None = None, seed: int = 42,
                 phase: str = PHASE_CONTROLS, **params) -> RunResult:
    if name not in _RUNNERS:
        raise ValueError(f"unknown scenario {name!r}; expected one of {SCENARIOS}")
    return _RUNNERS[name](controls=controls, seed=seed, phase=phase, **params)


def run_before_after(name: str, controls_after: ControlConfig, seed: int = 42, **params):
    """Baseline (no controls) vs with controls, same seed and parameters."""
    base = run_scenario(name, ControlConfig.none(), seed, PHASE_BASELINE, **params)
    post = run_scenario(name, controls_after, seed, PHASE_CONTROLS, **params)
    return base, post


def run_all(controls_after: ControlConfig, seed: int = 42) -> dict:
    return {n: run_before_after(n, controls_after, seed) for n in SCENARIOS}


ABLATION_COLUMNS = {
    "arp_spoofing": ["caches_poisoned", "diversion_rate_pct", "detection_count", "block_count"],
    "mitm": ["confidentiality_exposure_pct", "tampered_accepted", "tampered_detected", "detection_count", "block_count"],
    "ddos": ["legit_success_rate_pct", "avg_latency_ms_legit", "p95_latency_ms_legit", "availability_pct",
             "detection_count", "block_count"],
}


def run_layer_ablation(name: str, seed: int = 42, **params) -> list[dict]:
    """Defence-in-depth view: run the scenario with NO controls, then with each control
    alone, then with all controls. Shows which independent layer detects/blocks what."""
    from .schemas import CONTROL_FLAGS
    cols = ABLATION_COLUMNS[name]
    rows = []
    setups = [("none", ControlConfig.none())]
    setups += [(flag, ControlConfig(**{flag: True})) for flag in CONTROL_FLAGS]
    setups.append(("ids + ips", ControlConfig(ids=True, ips=True)))
    setups.append(("ALL layers", ControlConfig.all_on()))
    for label, cfg in setups:
        res = run_scenario(name, cfg, seed, PHASE_CONTROLS, **params)
        rows.append({"controls": label, **{c: res.metrics.get(c) for c in cols}})
    return rows
