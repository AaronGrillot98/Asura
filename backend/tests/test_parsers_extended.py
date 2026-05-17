"""Smoke tests for the 14 additional parsers wired in slice 2."""
from __future__ import annotations

from app.services.parsers import (
    bandit,
    bearer,
    brakeman,
    cargo_audit,
    eslint,
    gosec,
    govulncheck,
    httpx,
    naabu,
    npm_audit,
    pip_audit,
    sarif,
    subfinder,
    trufflehog,
)


def _assert_minimum(findings, *, scanner: str) -> None:
    assert findings, f"{scanner} parser produced no findings"
    for f in findings:
        assert f.scanner == scanner or scanner == "sarif"
        assert f.evidence, f"{scanner} finding {f.id} has no evidence"
        assert f.title
        assert f.severity is not None


def test_bandit_parser() -> None:
    raw = {
        "results": [{
            "test_id": "B105",
            "filename": "src/secret.py",
            "line_number": 7,
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": "Possible hardcoded password",
            "issue_cwe": {"id": "259"},
        }],
    }
    _assert_minimum(bandit.parse(raw), scanner="bandit")


def test_pip_audit_parser() -> None:
    raw = {
        "dependencies": [{
            "name": "requests",
            "version": "2.20.0",
            "vulns": [{"id": "PYSEC-2018-28", "fix_versions": ["2.20.1"], "description": "ReDoS in requests"}],
        }],
    }
    _assert_minimum(pip_audit.parse(raw), scanner="pip-audit")


def test_npm_audit_parser() -> None:
    raw = {
        "vulnerabilities": {
            "lodash": {
                "severity": "high",
                "via": [{"title": "Prototype pollution", "url": "https://github.com/advisories/GHSA-x"}],
                "fixAvailable": True,
            },
        },
    }
    _assert_minimum(npm_audit.parse(raw), scanner="npm-audit")


def test_cargo_audit_parser() -> None:
    raw = {
        "vulnerabilities": {
            "list": [{
                "advisory": {"id": "RUSTSEC-2020-0001", "description": "advisory text", "aliases": ["CVE-2020-1"]},
                "package": {"name": "rusty", "version": "0.1.0"},
            }],
        },
    }
    _assert_minimum(cargo_audit.parse(raw), scanner="cargo-audit")


def test_govulncheck_parser() -> None:
    raw = [{
        "osv": {
            "id": "GO-2023-0001",
            "summary": "Go module vuln",
            "affected": [{"package": {"name": "example.com/m"}}],
            "aliases": ["CVE-2023-0001"],
        }
    }]
    _assert_minimum(govulncheck.parse(raw), scanner="govulncheck")


def test_gosec_parser() -> None:
    raw = {
        "Issues": [{
            "rule_id": "G101",
            "severity": "HIGH",
            "confidence": "HIGH",
            "details": "Potential hardcoded credentials",
            "file": "main.go",
            "line": "12",
            "cwe": {"ID": "798"},
        }],
    }
    _assert_minimum(gosec.parse(raw), scanner="gosec")


def test_brakeman_parser() -> None:
    raw = {
        "warnings": [{
            "warning_type": "SQL Injection",
            "check_name": "SQL",
            "message": "Unescaped input in query",
            "file": "app/controllers/users_controller.rb",
            "line": 22,
            "confidence": "High",
        }],
    }
    _assert_minimum(brakeman.parse(raw), scanner="brakeman")


def test_eslint_parser() -> None:
    raw = [{
        "filePath": "src/app.js",
        "messages": [{
            "ruleId": "security/detect-object-injection",
            "severity": 2,
            "message": "Variable used as object key",
            "line": 14,
        }],
    }]
    _assert_minimum(eslint.parse(raw), scanner="eslint-security")


def test_bearer_parser() -> None:
    raw = {
        "high": [{
            "id": "ruby_lang_sensitive_data_in_logger",
            "title": "Sensitive data in logger",
            "description": "PII sent to logs",
            "filename": "app/log.rb",
            "line_number": 5,
            "cwe_ids": ["359"],
        }],
    }
    _assert_minimum(bearer.parse(raw), scanner="bearer")


def test_trufflehog_parser() -> None:
    raw = [{
        "DetectorName": "AWS",
        "Verified": True,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.env", "line": 3}}},
    }]
    _assert_minimum(trufflehog.parse(raw), scanner="trufflehog")


def test_subfinder_parser() -> None:
    raw = [{"host": "api.flightops.acme.example", "source": "crtsh"}]
    _assert_minimum(subfinder.parse(raw), scanner="subfinder")


def test_httpx_parser() -> None:
    raw = [{
        "url": "https://flightops.acme.example",
        "status_code": 200,
        "title": "FlightOps",
        "tech": ["nginx", "react"],
    }]
    _assert_minimum(httpx.parse(raw), scanner="httpx")


def test_naabu_parser() -> None:
    raw = [{"host": "edge-01.flightops.acme.example", "port": 8081, "protocol": "tcp"}]
    _assert_minimum(naabu.parse(raw), scanner="naabu")


def test_discovery_parser_handles_jsonl_and_bare_lines() -> None:
    from app.services.parsers import discovery
    raw_jsonl = '{"host":"a.example.com"}\n{"host":"b.example.com"}\n'
    out = discovery.parse(raw_jsonl, scanner="amass")
    assert {f.affected_asset for f in out} == {"a.example.com", "b.example.com"}
    assert all(f.scanner == "amass" for f in out)

    raw_bare = "x.example.com\ny.example.com\n"
    out2 = discovery.parse(raw_bare, scanner="assetfinder")
    assert {f.affected_asset for f in out2} == {"x.example.com", "y.example.com"}


def test_discovery_dispatch_for_each_recon_tool() -> None:
    from app.services.parsers import PARSERS
    expected = {
        "amass_json", "dnsx_json", "katana_json", "gau_json",
        "waybackurls_text", "hakrawler_json", "webanalyze_json",
        "whatweb_json", "wafw00f_json", "tlsx_json", "shuffledns_json",
        "assetfinder_text",
    }
    assert expected.issubset(set(PARSERS.keys()))


def test_sarif_generic_parser() -> None:
    raw = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{
                "ruleId": "js/sql-injection",
                "level": "error",
                "message": {"text": "SQL injection vulnerability"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/db.js"},
                        "region": {"startLine": 42},
                    }
                }],
            }],
        }],
    }
    out = sarif.parse(raw)
    assert out, "SARIF parser produced no findings"
    f = out[0]
    assert f.scanner == "codeql"
    assert f.affected_asset == "src/db.js"
    assert f.evidence and f.evidence[0].content_hash
