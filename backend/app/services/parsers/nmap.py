"""Nmap parser.

Accepts either an Nmap XML string or a parsed-host list of dicts. The XML
path uses Python's stdlib and tolerates partial output.
"""
from __future__ import annotations

from typing import Any, Iterable
from xml.etree import ElementTree as ET

from app.models.schemas import Confidence, Finding, Severity

from ._common import make_finding


def _hosts_from_xml(xml_text: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    hosts: list[dict[str, Any]] = []
    for host in root.iter("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else None
        ports: list[dict[str, Any]] = []
        for port in host.iter("port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            if state != "open":
                continue
            service_el = port.find("service")
            ports.append({
                "port": int(port.get("portid") or 0),
                "protocol": port.get("protocol"),
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
            })
        hosts.append({"address": address, "ports": ports})
    return hosts


def _normalize(raw: object) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        return _hosts_from_xml(raw)
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict) and "hosts" in raw:
        return list(raw["hosts"])
    return []


def parse(
    raw: object,
    *,
    project_id: str = "demo",
    scan_id: str | None = None,
    asset_id: str = "asset-host",
    is_demo_data: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    for host in _normalize(raw):
        address = host.get("address") or "unknown"
        for port in host.get("ports", []):
            service = port.get("service") or "service"
            findings.append(
                make_finding(
                    project_id=project_id,
                    scan_id=scan_id,
                    asset_id=asset_id,
                    scanner="nmap",
                    title=f"Open service on {address}:{port.get('port')}/{port.get('protocol')}",
                    category="network",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    impact=f"Service '{service}' is reachable on the target interface.",
                    recommendation=f"Bind the service to a private interface or restrict access via firewall rules.",
                    reproduction=f"nmap -sV reported {service} on tcp/{port.get('port')}",
                    false_positive_reasoning="Nmap confirmed an open port and service banner.",
                    raw={"address": address, **port},
                    summary=f"Open {service} service on {address}:{port.get('port')}.",
                    affected_asset=address,
                    affected_component=f"{port.get('protocol')}/{port.get('port')}",
                    is_demo_data=is_demo_data,
                )
            )
    return findings
