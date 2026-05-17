from datetime import datetime, timezone

from app.models.schemas import Confidence, Evidence, EvidenceType, Finding, Severity
from app.services.fingerprint import dedupe_findings, finding_fingerprint


def _finding(fid: str) -> Finding:
    ev = Evidence(
        id=f"ev-{fid}",
        finding_id=fid,
        evidence_type=EvidenceType.scanner_output,
        scanner="semgrep",
        raw={"rule": "asura.auth-missing", "file": "src/routes/admin.ts"},
        summary="x",
        file_path="src/routes/admin.ts",
        captured_at=datetime.now(timezone.utc),
    )
    return Finding(
        id=fid,
        project_id="demo",
        asset_id="asset-repo",
        scanner="semgrep",
        title=f"Missing auth check {fid}",
        category="code",
        severity=Severity.high,
        confidence=Confidence.medium,
        affected_asset="git://acme/flightops-platform",
        affected_component="src/routes/admin.ts:42",
        impact="x",
        recommendation="x",
        reproduction="x",
        false_positive_reasoning="x",
        evidence=[ev],
    )


def test_same_inputs_produce_same_fingerprint() -> None:
    a = _finding("a")
    b = _finding("b")
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_dedupe_collapses_duplicates_and_stamps_hash() -> None:
    a = _finding("a")
    b = _finding("b")
    out = dedupe_findings([a, b])
    assert len(out) == 1
    assert out[0].fingerprint_hash
    assert out[0].id == "a"  # first kept


def test_fingerprint_changes_when_path_changes() -> None:
    a = _finding("a")
    b = _finding("b")
    b.evidence[0].file_path = "src/routes/other.ts"
    b.evidence[0].raw["file"] = "src/routes/other.ts"
    assert finding_fingerprint(a) != finding_fingerprint(b)
