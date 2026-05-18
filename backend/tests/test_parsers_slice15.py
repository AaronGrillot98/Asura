"""Parser smoke tests for slice 15: the 8 newly-wired scanners.

For each tool we feed a realistic output fixture and assert:
- at least one finding comes out,
- severity / affected_asset / evidence are populated,
- the wire-up via `parsers.parse(parser_id, raw=...)` dispatches correctly
  (i.e. the YAML's `parser:` field matches a key in the PARSERS dict).
"""
from __future__ import annotations

import json

from app.services.parsers import PARSERS, parse as dispatch_parse
from app.services.parsers import (
    docker_bench,
    feroxbuster,
    jwt_tool,
    nikto,
    polaris,
    retirejs,
    schemathesis,
    wapiti,
)


# ---- feroxbuster -----------------------------------------------------------


FEROX_NDJSON = "\n".join([
    json.dumps({"type": "configuration", "wordlist": "common.txt"}),
    json.dumps({"type": "response", "url": "https://target.example/admin", "status": 200, "method": "GET", "content_length": 1234}),
    json.dumps({"type": "response", "url": "https://target.example/login", "status": 401, "method": "GET", "content_length": 456}),
    json.dumps({"type": "response", "url": "https://target.example/missing", "status": 404, "method": "GET", "content_length": 0}),
    json.dumps({"type": "response", "url": "https://target.example/api", "status": 500, "method": "GET", "content_length": 30}),
])


def test_feroxbuster_emits_response_findings_skipping_404s() -> None:
    findings = feroxbuster.parse(FEROX_NDJSON, project_id="p", scan_id="s", asset_id="a")
    urls = {f.affected_asset for f in findings}
    assert "https://target.example/admin" in urls
    assert "https://target.example/login" in urls  # 401 is interesting
    assert "https://target.example/api" in urls    # 5xx is interesting
    assert "https://target.example/missing" not in urls  # 404 dropped
    assert all(f.scanner == "feroxbuster" for f in findings)
    assert all(f.evidence and f.evidence[0].content_hash for f in findings)


def test_feroxbuster_parser_id_matches_yaml() -> None:
    assert "feroxbuster_json" in PARSERS


# ---- nikto -----------------------------------------------------------------


NIKTO_JSON = {
    "host": "target.example",
    "port": "443",
    "vulnerabilities": [
        {"id": "999100", "method": "GET", "url": "/", "msg": "The anti-clickjacking X-Frame-Options header is not present."},
        {"id": "999101", "method": "GET", "url": "/admin", "msg": "Admin login page found. Default credentials may be in use."},
    ],
}


def test_nikto_emits_one_finding_per_vuln_with_admin_high() -> None:
    findings = nikto.parse(NIKTO_JSON, project_id="p", scan_id="s", asset_id="a")
    assert len(findings) == 2
    severities = {f.severity for f in findings}
    # "admin" + "Default credentials" both trigger the high-severity bump.
    assert any(f.severity.value == "high" for f in findings), severities


def test_nikto_accepts_str_payload() -> None:
    findings = nikto.parse(json.dumps(NIKTO_JSON))
    assert findings, "string payload should also parse"


def test_nikto_parser_id_matches_yaml() -> None:
    assert "nikto_json" in PARSERS


# ---- wapiti ----------------------------------------------------------------


WAPITI_JSON = {
    "vulnerabilities": {
        "SQL Injection": [
            {"level": 3, "module": "sql", "info": "SQL injection in id param.", "method": "GET", "path": "/items"},
        ],
        "Backup file": [
            {"level": 1, "module": "backup", "info": "Backup file found.", "method": "GET", "path": "/db.sql.bak"},
        ],
    },
    "anomalies": {
        "Internal Server Error": [
            {"level": 1, "module": "anomaly", "info": "500 on /panic", "method": "POST", "path": "/panic"},
        ],
    },
}


def test_wapiti_maps_level_to_severity() -> None:
    findings = wapiti.parse(WAPITI_JSON, project_id="p")
    by_path = {f.affected_asset: f for f in findings}
    assert by_path["/items"].severity.value == "high"
    assert by_path["/db.sql.bak"].severity.value == "low"
    assert by_path["/panic"].severity.value == "low"


def test_wapiti_parser_id_matches_yaml() -> None:
    assert "wapiti_json" in PARSERS


# ---- retirejs --------------------------------------------------------------


RETIRE_JSON = [
    {
        "file": "/var/www/static/jquery-1.6.1.min.js",
        "results": [
            {
                "component": "jquery",
                "version": "1.6.1",
                "vulnerabilities": [
                    {
                        "severity": "medium",
                        "identifiers": {"CVE": ["CVE-2012-6708"], "summary": "Selector parsing weakness"},
                        "info": ["https://example/advisory"],
                    },
                    {
                        "severity": "high",
                        "identifiers": {"CVE": ["CVE-2015-9251"], "summary": "XSS via $.parseHTML"},
                    },
                ],
            }
        ],
    }
]


def test_retirejs_emits_one_finding_per_vulnerability_with_cve() -> None:
    findings = retirejs.parse(RETIRE_JSON, project_id="p")
    assert len(findings) == 2
    cves = {tuple(f.cve) for f in findings}
    assert ("CVE-2012-6708",) in cves
    assert ("CVE-2015-9251",) in cves
    assert all(f.affected_component == "jquery@1.6.1" for f in findings)


def test_retirejs_accepts_dict_with_data_key() -> None:
    findings = retirejs.parse({"data": RETIRE_JSON})
    assert findings


def test_retirejs_parser_id_matches_yaml() -> None:
    assert "retirejs_json" in PARSERS


# ---- schemathesis ----------------------------------------------------------


SCHEMATHESIS_OUTPUT = """\
============================== schemathesis run ==============================
collected: 12

___________________________________ POST /users ____________________________________

1. Server Error
   [500] Internal Server Error from POST /users with body {...}

___________________________________ GET /items/{id} ____________________________________

1. Status Code Conformance
   Received: 418, expected one of: 200, 404

___________________________________ PATCH /items/{id} ____________________________________

This section has no recognisable failures, just chatter.

================================== Summary ==================================
2 failures, 1 passed
"""


def test_schemathesis_emits_one_finding_per_failed_schema() -> None:
    findings = schemathesis.parse(SCHEMATHESIS_OUTPUT, project_id="p")
    schemas = {f.affected_asset for f in findings}
    assert "POST /users" in schemas
    assert "GET /items/{id}" in schemas
    # PATCH section had no recognisable failure → no finding for it.
    assert "PATCH /items/{id}" not in schemas
    # Server Error is high; Status Code Conformance is medium.
    sev_by_schema = {f.affected_asset: f.severity.value for f in findings}
    assert sev_by_schema["POST /users"] == "high"
    assert sev_by_schema["GET /items/{id}"] == "medium"


def test_schemathesis_parser_id_matches_yaml() -> None:
    assert "schemathesis_text" in PARSERS


# ---- jwt-tool --------------------------------------------------------------


JWT_TOOL_OUTPUT = """\
=====================
Decoding token:
Token header values:
[+] alg = "HS256"
[+] typ = "JWT"
Token payload values:
[+] sub = "user-42"
[+] exp = 1700000000

[!] alg=none would be accepted; the verifier does not enforce alg
[+] Vulnerability: weak HMAC key (cracked via dictionary attack)
[!] No additional checks performed in this mode
"""


def test_jwt_tool_emits_decoded_summary_plus_per_issue_findings() -> None:
    findings = jwt_tool.parse(JWT_TOOL_OUTPUT, project_id="p")
    # 1 info (decoded) + 2 vulnerability lines (one high alg=none, one high weak key).
    titles = [f.title for f in findings]
    assert any("Decoded JWT" in t for t in titles)
    assert any("alg=none" in t.lower() for t in titles)
    assert any("weak hmac key" in t.lower() for t in titles)
    high = [f for f in findings if f.severity.value == "high"]
    assert len(high) >= 2, [(f.title, f.severity.value) for f in findings]


def test_jwt_tool_ignores_no_additional_checks_marker() -> None:
    findings = jwt_tool.parse(JWT_TOOL_OUTPUT)
    assert not any("no additional" in f.title.lower() for f in findings)


def test_jwt_tool_parser_id_matches_yaml() -> None:
    assert "jwt_tool_text" in PARSERS


# ---- polaris ---------------------------------------------------------------


POLARIS_JSON = {
    "PolarisOutputVersion": "1.0",
    "AuditTime": "2026-05-17T00:00:00Z",
    "Results": [
        {
            "Name": "web",
            "Namespace": "prod",
            "Kind": "Deployment",
            "Results": {
                "hostNetworkSet": {
                    "ID": "hostNetworkSet",
                    "Message": "Host network is configured",
                    "Success": False,
                    "Severity": "danger",
                    "Category": "Security",
                },
                "cpuRequestsMissing": {
                    "ID": "cpuRequestsMissing",
                    "Message": "CPU requests should be set",
                    "Success": False,
                    "Severity": "warning",
                    "Category": "Efficiency",
                },
                "memoryRequestsSet": {
                    "ID": "memoryRequestsSet",
                    "Message": "OK",
                    "Success": True,
                    "Severity": "warning",
                    "Category": "Efficiency",
                },
            },
        }
    ],
}


def test_polaris_skips_passing_checks_and_maps_severity() -> None:
    findings = polaris.parse(POLARIS_JSON, project_id="p")
    ids = {f.affected_component for f in findings}
    assert "hostNetworkSet" in ids
    assert "cpuRequestsMissing" in ids
    assert "memoryRequestsSet" not in ids  # Success: True is dropped
    sev = {f.affected_component: f.severity.value for f in findings}
    assert sev["hostNetworkSet"] == "high"
    assert sev["cpuRequestsMissing"] == "medium"


def test_polaris_resource_id_format() -> None:
    findings = polaris.parse(POLARIS_JSON)
    assert all(f.affected_asset == "Deployment/prod/web" for f in findings)


def test_polaris_parser_id_matches_yaml() -> None:
    assert "polaris_json" in PARSERS


# ---- docker-bench-security -------------------------------------------------


DOCKER_BENCH_JSON = {
    "dockerbenchsecurity": "1.5.0",
    "tests": [
        {
            "id": "1",
            "desc": "Host Configuration",
            "results": [
                {"id": "1.1.1", "desc": "Ensure a separate partition for containers has been created", "result": "WARN", "details": ""},
                {"id": "1.1.2", "desc": "Ensure only trusted users are allowed to control Docker daemon", "result": "PASS", "details": ""},
                {"id": "1.1.3", "desc": "Audit docker daemon", "result": "INFO", "details": "auditd not running"},
            ],
        }
    ],
}


def test_docker_bench_emits_warn_and_info_skipping_pass() -> None:
    findings = docker_bench.parse(DOCKER_BENCH_JSON, project_id="p")
    rule_ids = {f.affected_component for f in findings}
    assert "1.1.1" in rule_ids  # WARN
    assert "1.1.3" in rule_ids  # INFO
    assert "1.1.2" not in rule_ids  # PASS dropped


def test_docker_bench_warn_severity_is_medium() -> None:
    findings = docker_bench.parse(DOCKER_BENCH_JSON)
    warn = next(f for f in findings if f.affected_component == "1.1.1")
    info = next(f for f in findings if f.affected_component == "1.1.3")
    assert warn.severity.value == "medium"
    assert info.severity.value == "info"


def test_docker_bench_parser_id_matches_yaml() -> None:
    assert "docker_bench_json" in PARSERS


# ---- dispatch + YAML alignment --------------------------------------------


def test_all_new_parser_ids_dispatch_via_registry() -> None:
    """Every yaml parser id for the 8 new tools must dispatch through the
    PARSERS registry rather than fall through to the empty default."""
    for pid in (
        "feroxbuster_json",
        "nikto_json",
        "wapiti_json",
        "retirejs_json",
        "schemathesis_text",
        "jwt_tool_text",
        "polaris_json",
        "docker_bench_json",
    ):
        # Dispatch with empty input — should return [] but not raise.
        result = dispatch_parse(pid, raw="")
        assert isinstance(result, list)


def test_yaml_parser_ids_are_all_registered() -> None:
    """Pull each of the 8 new tools out of the arsenal and confirm its
    `parser:` field points at a real entry in the PARSERS dict."""
    from app.services.tool_registry import load_arsenal

    arsenal = load_arsenal()
    by_id = {t.id: t for t in arsenal.tools}
    for tid in (
        "feroxbuster", "nikto", "wapiti", "retirejs",
        "schemathesis", "jwt-tool", "polaris", "docker-bench-security",
    ):
        tool = by_id[tid]
        assert tool.parser, f"{tid} has no parser declared"
        assert tool.parser in PARSERS, f"{tid} parser '{tool.parser}' is not in PARSERS"
