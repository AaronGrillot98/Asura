from app.services.tool_registry import load_arsenal


SPEC_90 = {
    "nmap", "nuclei", "semgrep", "trivy", "gitleaks", "osv-scanner", "checkov",
    "zap", "syft", "grype",
    "codeql", "bandit", "pip-audit", "npm-audit", "cargo-audit", "govulncheck",
    "gosec", "brakeman", "eslint-security", "bearer",
    "subfinder", "amass", "httpx", "naabu", "dnsx", "katana", "gau",
    "waybackurls", "hakrawler", "webanalyze", "whatweb", "wafw00f", "tlsx",
    "shuffledns", "assetfinder",
    "ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun", "nikto", "wapiti",
    "dalfox", "kxss", "linkfinder", "secretfinder", "retirejs", "corsy",
    "crlfuzz", "openredirex",
    "schemathesis", "kiterunner", "jwt-tool", "graphql-voyager", "inql",
    "graphql-cop", "postman-importer", "openapi-parser", "restler",
    "trufflehog", "detect-secrets", "whispers", "detect-secrets-baseline",
    "kics", "terrascan", "tfsec-compatible", "cloudsplaining", "prowler",
    "scoutsuite", "steampipe", "parliament", "cfn-nag",
    "kube-score", "kube-bench", "kubescape", "polaris", "docker-bench-security",
    "falco", "sigma", "yara", "suricata-rules", "zeek", "osquery",
    "chainsaw", "hayabusa", "velociraptor", "volatility3", "plaso", "timesketch",
    "garak",
}


def test_arsenal_covers_the_90_spec_ids() -> None:
    arsenal = load_arsenal()
    ids = {tool.id for tool in arsenal.tools}
    missing = SPEC_90 - ids
    assert not missing, f"Missing spec tools: {sorted(missing)}"


def test_planned_catalog_additions_have_no_runnable_commands() -> None:
    # The 47 tools added to reach the 90-spec catalog are registered as
    # catalog-only entries: planned status and no command templates. Older
    # entries may carry placeholder commands validated by the registry
    # contract; only this batch is checked here.
    arsenal = load_arsenal()
    # Several entries have graduated from catalog-only to first-class runners:
    #   - trufflehog (slice 2)
    #   - ffuf, gobuster, dirsearch, kube-bench, kubescape, kube-score, prowler
    #     (slice 10: fuzzers + K8s/cloud)
    #   - feroxbuster, nikto, wapiti, retirejs, schemathesis, jwt-tool,
    #     polaris, docker-bench-security (slice 15: more catalog tools wired)
    # Anything still in this set is intentionally not yet runnable.
    catalog_only_additions = {
        "arjun",
        "kxss", "linkfinder", "secretfinder", "corsy", "crlfuzz",
        "openredirex", "kiterunner", "graphql-voyager", "inql",
        "graphql-cop", "restler", "postman-importer", "openapi-parser",
        "detect-secrets", "whispers", "detect-secrets-baseline",
        "kics", "terrascan", "tfsec-compatible", "cloudsplaining", "scoutsuite",
        "steampipe", "parliament", "cfn-nag",
        "falco",
        "suricata-rules", "zeek", "osquery", "chainsaw", "hayabusa",
        "velociraptor", "volatility3", "plaso", "timesketch",
    }
    by_id = {tool.id: tool for tool in arsenal.tools}
    for tid in catalog_only_additions:
        assert tid in by_id, f"Spec tool {tid} is missing from the catalog"
        assert not by_id[tid].commands, f"Catalog-only tool {tid} must not define commands"


def test_lab_only_tools_set_requires_lab_mode() -> None:
    arsenal = load_arsenal()
    forensic_ids = {"chainsaw", "hayabusa", "velociraptor", "volatility3", "plaso", "timesketch"}
    for tool in arsenal.tools:
        if tool.id in forensic_ids:
            assert tool.requires_lab_mode is True, f"{tool.id} must require lab mode"
            assert "lab" in [m.value for m in tool.modes]


def test_blocked_tools_have_no_commands_or_executable() -> None:
    arsenal = load_arsenal()
    blocked = [t for t in arsenal.tools if t.execution == "blocked"]
    assert blocked, "Catalog should keep at least one blocked exemplar"
    for tool in blocked:
        assert not tool.commands
        assert not tool.executable
        assert not tool.modes


def test_arsenal_summary_includes_blocked_capabilities() -> None:
    arsenal = load_arsenal()
    assert arsenal.blocked_capabilities
    assert any("malware" in cap.lower() for cap in arsenal.blocked_capabilities)
