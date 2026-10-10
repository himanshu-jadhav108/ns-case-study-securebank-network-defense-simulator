"""Shared constants and data structures.

Everything produced by the Cloud simulator is labelled SIMULATED.
Everything measured by the local harness is labelled LOCAL MEASURED.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

MODE_SIM = "SIMULATED"
MODE_LOCAL = "LOCAL MEASURED"
SOURCE_SIM = "cloud_simulator:src/simulator.py"
SOURCE_LOCAL = "local_lab:test_harness.py"

PHASE_BASELINE = "baseline"
PHASE_CONTROLS = "with_controls"

SCENARIOS = ("arp_spoofing", "mitm", "ddos")
SCENARIO_LABELS = {
    "arp_spoofing": "ARP spoofing (conflicting IP-to-MAC mappings)",
    "mitm": "Man-in-the-middle (message confidentiality / integrity)",
    "ddos": "DDoS-style service disruption (simulated workload)",
}

# Long-format CSV schema used by both the simulator and the local harness.
CSV_COLUMNS = [
    "run_id", "mode", "source", "scenario", "phase",
    "metric", "value", "seed", "controls_active",
]

# Independent control layers (defence-in-depth).
CONTROL_FLAGS = (
    "segmentation", "firewall", "arp_protection", "ids", "ips",
    "rate_limit", "access_control", "hmac_integrity", "encryption",
)

CONTROL_LABELS = {
    "segmentation": "Network segmentation (logical zones)",
    "firewall": "Firewall (application-layer allow/deny rules)",
    "arp_protection": "ARP protection (trusted bindings, DAI-like)",
    "ids": "IDS (rule-based detection, alert only)",
    "ips": "IPS (block after policy triggers)",
    "rate_limit": "Rate limiting (per source)",
    "access_control": "Access control (token authentication/authorisation)",
    "hmac_integrity": "Message integrity (HMAC-SHA256)",
    "encryption": "Transport encryption (SIMULATED confidentiality only)",
}


@dataclass
class ControlConfig:
    segmentation: bool = False
    firewall: bool = False
    arp_protection: bool = False
    ids: bool = False
    ips: bool = False
    rate_limit: bool = False
    access_control: bool = False
    hmac_integrity: bool = False
    encryption: bool = False
    rate_limit_per_tick: int = 5      # max requests per source per simulated second
    ids_rate_threshold: int = 30      # IDS alert when a source exceeds this per tick
    ids_failed_threshold: int = 5     # IDS alert after this many failed requests

    def active(self) -> list[str]:
        return [n for n in CONTROL_FLAGS if getattr(self, n)]

    def any_active(self) -> bool:
        return bool(self.active())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def none(cls) -> "ControlConfig":
        return cls()

    @classmethod
    def all_on(cls) -> "ControlConfig":
        return cls(**{n: True for n in CONTROL_FLAGS})


@dataclass
class Event:
    tick: int
    layer: str
    action: str          # deny | block | detect | throttle | info | compromise
    source: str
    detail: str
    scenario: str = ""
    phase: str = ""
    mode: str = MODE_SIM

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunResult:
    scenario: str
    phase: str
    seed: int
    controls: dict
    metrics: dict
    events: list[Event]
    records: list[dict] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    residual_risk: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    mode: str = MODE_SIM

    def controls_active(self) -> list[str]:
        return [k for k in CONTROL_FLAGS if self.controls.get(k)]
