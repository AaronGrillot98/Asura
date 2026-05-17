"""Explicit list of capabilities Asura refuses to ship.

Surfaced in the API (`GET /api/safety/blocked`) and in the docs, so the safety
contract has one canonical source. Anything added here should also be reflected
in `docs/SAFETY_MODEL.md`.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BlockedCapability:
    id: str
    label: str
    rationale: str


BLOCKED_CAPABILITIES: tuple[BlockedCapability, ...] = (
    BlockedCapability(
        id="malware",
        label="Malware authoring or weaponization",
        rationale="Asura assists authorized testing; it does not build attacker tooling.",
    ),
    BlockedCapability(
        id="persistence",
        label="Persistence mechanisms",
        rationale="Footholds and post-exploitation maintenance are out of scope.",
    ),
    BlockedCapability(
        id="credential_theft",
        label="Credential theft",
        rationale="Keyloggers, dumpers, and harvesters fall outside authorized security testing.",
    ),
    BlockedCapability(
        id="phishing",
        label="Phishing kit generation",
        rationale="Phishing infrastructure targets people, not authorized assets.",
    ),
    BlockedCapability(
        id="ransomware",
        label="Ransomware or destructive payloads",
        rationale="Destructive operations are never enabled, even in lab mode.",
    ),
    BlockedCapability(
        id="botnet",
        label="Botnet command and control",
        rationale="C2 frameworks for unauthorized targets are not supported.",
    ),
    BlockedCapability(
        id="destructive_payload",
        label="Destructive exploitation payloads",
        rationale="Validation in lab mode is bounded, logged, and non-destructive.",
    ),
    BlockedCapability(
        id="stealth",
        label="Detection evasion / AV bypass",
        rationale="Asura is loud by design; evasion conflicts with the audit trail.",
    ),
    BlockedCapability(
        id="unauthorized_exploitation",
        label="Unauthorized exploitation",
        rationale="Every exploit step requires explicit authorization and lab mode.",
    ),
    BlockedCapability(
        id="data_exfiltration",
        label="Data exfiltration",
        rationale="Evidence stays inside the workspace; exfil tooling has no role here.",
    ),
    BlockedCapability(
        id="ddos",
        label="Denial-of-service tooling",
        rationale="Volume-based attacks are out of scope regardless of authorization.",
    ),
)


def as_dicts() -> list[dict[str, str]]:
    """Return blocked capabilities as plain dicts for API surface."""
    return [{"id": bc.id, "label": bc.label, "rationale": bc.rationale} for bc in BLOCKED_CAPABILITIES]


def labels() -> list[str]:
    """Short labels only — used by older arsenal serialization paths."""
    return [bc.label for bc in BLOCKED_CAPABILITIES]
