"""Smoke-tests for the 10 core parsers: each must normalize a fixture into ≥1 Finding."""
from app.services.parsers import (
    checkov,
    gitleaks,
    grype,
    nmap,
    nuclei,
    osv,
    semgrep,
    syft,
    trivy,
    zap,
)


def _assert_minimum(findings, *, scanner: str) -> None:
    assert findings, f"{scanner} parser produced no findings"
    for f in findings:
        assert f.scanner == scanner
        assert f.evidence, f"{scanner} finding {f.id} has no evidence"
        assert f.title
        assert f.severity is not None


def test_nmap_parser() -> None:
    xml = """<?xml version='1.0'?>
<nmaprun><host><address addr='10.10.7.20' addrtype='ipv4'/>
<ports><port portid='80' protocol='tcp'><state state='open'/><service name='http' product='nginx'/></port></ports></host></nmaprun>"""
    _assert_minimum(nmap.parse(xml), scanner="nmap")


def test_nuclei_parser() -> None:
    raw = [{
        "template-id": "http/exposures/panels/admin-panel",
        "matched-at": "https://demo.local/admin",
        "info": {"name": "Admin Panel", "severity": "high", "description": "panel exposure"},
    }]
    _assert_minimum(nuclei.parse(raw), scanner="nuclei")


def test_semgrep_parser() -> None:
    raw = {"results": [{
        "check_id": "asura.auth-missing",
        "path": "src/routes/admin.ts",
        "start": {"line": 42},
        "extra": {"severity": "ERROR", "message": "missing auth guard"},
    }]}
    _assert_minimum(semgrep.parse(raw), scanner="semgrep")


def test_trivy_parser() -> None:
    raw = {"Results": [{
        "Target": "app",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-0286",
            "PkgName": "openssl",
            "InstalledVersion": "3.0.2",
            "FixedVersion": "3.0.8",
            "Severity": "HIGH",
            "Description": "OpenSSL X.509 issue.",
        }],
    }]}
    _assert_minimum(trivy.parse(raw), scanner="trivy")


def test_gitleaks_parser() -> None:
    raw = [{"RuleID": "asura-admin-token", "File": "config/demo.env", "StartLine": 12}]
    _assert_minimum(gitleaks.parse(raw), scanner="gitleaks")


def test_osv_parser() -> None:
    raw = {"results": [{
        "source": {"path": "package-lock.json"},
        "packages": [{
            "package": {"name": "axios", "version": "0.20.0"},
            "vulnerabilities": [{
                "id": "GHSA-jx5p-h2ch-7p2v",
                "aliases": ["CVE-2020-28168"],
                "summary": "SSRF in axios",
            }],
        }],
    }]}
    _assert_minimum(osv.parse(raw), scanner="osv-scanner")


def test_checkov_parser() -> None:
    raw = {"results": {"failed_checks": [{
        "check_id": "CKV_AWS_111",
        "check_name": "Ensure IAM has no wildcards",
        "file_path": "terraform/iam.tf",
        "resource": "aws_iam_policy.admin",
        "severity": "HIGH",
    }]}}
    _assert_minimum(checkov.parse(raw), scanner="checkov")


def test_zap_parser() -> None:
    raw = {"site": [{"alerts": [{
        "name": "CORS Misconfiguration",
        "riskdesc": "Medium",
        "url": "https://demo.local/api",
        "desc": "Reflected Origin",
        "solution": "Use an explicit allowlist",
        "cweid": "942",
    }]}]}
    _assert_minimum(zap.parse(raw), scanner="zap")


def test_syft_parser() -> None:
    raw = {"artifacts": [{"name": "openssl", "version": "3.0.2"}]}
    _assert_minimum(syft.parse(raw), scanner="syft")


def test_grype_parser() -> None:
    raw = {"matches": [{
        "vulnerability": {
            "id": "CVE-2023-0286",
            "severity": "High",
            "description": "OpenSSL CVE",
            "fix": {"versions": ["3.0.8"]},
        },
        "artifact": {"name": "openssl", "version": "3.0.2"},
    }]}
    _assert_minimum(grype.parse(raw), scanner="grype")
