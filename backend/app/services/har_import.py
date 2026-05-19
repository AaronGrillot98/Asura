"""HAR (HTTP Archive) ingestion.

Bug-bounty hunters and pentesters spend most of their day browsing a
target through a proxy (Burp Pro, mitmproxy, Caido, even DevTools). The
single most useful artifact that comes out of that workflow is the HAR
file — a JSON dump of every request the browser made, including
method, URL, headers, params, response status, and content type.

HAR is the lingua franca: Burp exports it from Project options →
Misc → Logger; mitmproxy ships a `har_dump` addon; Chrome and Firefox
DevTools export it natively. We accept the JSON, walk every entry,
and produce:

1. A **list of unique hosts** — each becomes a Target row in the project
   (deduped against existing targets so re-importing is idempotent).
2. An **endpoint catalog** keyed by (method, host, path) with the union
   of query / body / header param names observed. This is the raw
   material for IDOR / BAC / parameter-discovery testing later.
3. A **status histogram** — surfaces which paths returned 401/403 vs.
   200, so a hunter can see at a glance "what's behind auth."
4. A **JS file inventory** — content-type or extension matches feed
   future LinkFinder / SecretFinder passes.

Out of scope this slice:
- Auto-creating Findings. The catalog is a *target inventory*, not
  a finding list.
- Templating numeric path segments (`/users/123` → `/users/{id}`).
  Useful but adds heuristics; keep paths literal for v1.
- Native Burp XML or mitmproxy `.mitm` binary format. Both tools
  export HAR; document that path instead of expanding our parser
  surface.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit
from uuid import uuid4

from app.models.schemas import (
    HarEndpoint,
    HarImportSummary,
    Project,
    Target,
)


# Schemes we don't care about — data: and ws:/wss: aren't targets.
_HTTP_SCHEMES = {"http", "https"}

# Content-type / extension heuristics for JS detection.
_JS_MIMES = {"application/javascript", "text/javascript", "application/x-javascript"}


class HarParseError(ValueError):
    """Raised when the uploaded blob doesn't look like a HAR document."""


def parse_har_bytes(blob: bytes) -> dict[str, Any]:
    """Decode + validate the HAR JSON. Raises HarParseError on malformed
    input rather than letting json.JSONDecodeError or KeyError surface
    raw."""
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HarParseError(f"Could not decode upload as UTF-8: {exc}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HarParseError(f"Upload is not valid JSON: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise HarParseError("HAR root must be a JSON object.")
    log = doc.get("log")
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise HarParseError("Missing required `log.entries` array.")
    return doc


def ingest_har(
    *,
    repos,
    project: Project,
    har_doc: dict[str, Any],
    respect_scope: bool = False,
) -> HarImportSummary:
    """Walk the HAR entries, build the catalog, and persist new Targets.

    When `respect_scope=True`, entries whose host falls outside
    `project.scope_rules.allowed_domains` (or `allowed_urls`) are
    dropped with a `skipped` reason — useful for bug-bounty workflows
    where the proxy captured third-party CDN/analytics traffic that
    isn't in scope.
    """
    entries = har_doc.get("log", {}).get("entries", [])
    by_host: dict[str, set[str]] = {}
    by_endpoint: dict[tuple[str, str, str], HarEndpoint] = {}
    status_buckets: dict[str, int] = {}
    js_files: set[str] = set()
    auth_required: set[str] = set()
    skipped: list[str] = []
    processed = 0

    allowed_hosts = _scope_hosts(project) if respect_scope else None

    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            skipped.append("entry is not a JSON object")
            continue
        request = raw_entry.get("request") or {}
        response = raw_entry.get("response") or {}
        url = request.get("url")
        method = (request.get("method") or "GET").upper()
        if not isinstance(url, str):
            skipped.append("entry missing request.url")
            continue
        try:
            parts = urlsplit(url)
        except ValueError:
            skipped.append(f"unparseable url: {url[:80]}")
            continue
        scheme = (parts.scheme or "").lower()
        if scheme not in _HTTP_SCHEMES:
            skipped.append(f"non-http scheme: {scheme or '<empty>'}")
            continue
        host = (parts.hostname or "").lower()
        if not host:
            skipped.append(f"missing host in url: {url[:80]}")
            continue
        if allowed_hosts is not None and not _host_in_scope(host, allowed_hosts):
            skipped.append(f"out of scope: {host}")
            continue

        path = parts.path or "/"
        processed += 1
        by_host.setdefault(host, set()).add(path)

        # Status code histogram + auth-required heuristic.
        status = response.get("status")
        if isinstance(status, int):
            bucket = f"{status // 100}xx"
            status_buckets[bucket] = status_buckets.get(bucket, 0) + 1
            if status in (401, 403):
                auth_required.add(f"{method} {host}{path}")

        # JS file inventory — both by content-type and by .js extension.
        mime = ((response.get("content") or {}).get("mimeType") or "").split(";")[0].strip().lower()
        if mime in _JS_MIMES or path.endswith(".js"):
            js_files.add(f"{scheme}://{host}{path}")

        # Per-endpoint catalog.
        key = (method, host, path)
        endpoint = by_endpoint.get(key)
        if endpoint is None:
            endpoint = HarEndpoint(
                method=method,
                host=host,
                path=path,
                sample_url=url,
                status_codes=[],
                param_names=[],
                seen_count=0,
            )
            by_endpoint[key] = endpoint
        endpoint.seen_count += 1
        if isinstance(status, int) and status not in endpoint.status_codes:
            endpoint.status_codes.append(status)
        for name in _extract_param_names(request):
            if name and name not in endpoint.param_names:
                endpoint.param_names.append(name)

    # Materialize Target rows for each unique host that isn't already
    # registered against this project.
    existing_values = {t.value for t in repos.targets.list() if t.project_id == project.id}
    new_targets: list[Target] = []
    for host in sorted(by_host):
        if host in existing_values:
            continue
        target = Target(
            id=f"target-{uuid4().hex[:10]}",
            project_id=project.id,
            kind="domain",
            value=host,
            authorized=False,  # explicitly NOT authorized — user must
                               # opt-in active scans per scope rules
            lab_mode_enabled=False,
            owned_internal=False,
            notes=f"Imported from HAR capture ({len(by_host[host])} unique path(s) observed)",
            created_at=datetime.now(timezone.utc),
            is_demo_data=False,
        )
        repos.targets.add(target)
        new_targets.append(target)

    return HarImportSummary(
        project_id=project.id,
        entries_processed=processed,
        hosts=sorted(by_host.keys()),
        endpoints=sorted(by_endpoint.values(), key=lambda e: (e.host, e.path, e.method)),
        js_files=sorted(js_files),
        auth_required_paths=sorted(auth_required),
        status_buckets=status_buckets,
        skipped=skipped,
        new_targets=new_targets,
        respect_scope=respect_scope,
    )


def _extract_param_names(request: dict) -> Iterable[str]:
    """Pull param names from queryString, postData.params, and the
    parsed query of the URL itself (in that order, deduped by the
    caller)."""
    for q in request.get("queryString") or []:
        if isinstance(q, dict):
            name = q.get("name")
            if isinstance(name, str):
                yield name
    post = request.get("postData") or {}
    for p in post.get("params") or []:
        if isinstance(p, dict):
            name = p.get("name")
            if isinstance(name, str):
                yield name


def _scope_hosts(project: Project) -> set[str]:
    """Compose the set of hosts considered in-scope from project rules."""
    rules = project.scope_rules
    out: set[str] = set()
    for domain in rules.domains or []:
        out.add(domain.lower().strip())
    for url in rules.urls or []:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host:
            out.add(host.lower())
    return out


def _host_in_scope(host: str, allowed_hosts: set[str]) -> bool:
    """Match host exactly OR allow apex-domain wildcards.

    `allowed_hosts={"example.com"}` matches `example.com`,
    `api.example.com`, `staging.example.com`, but NOT `evilexample.com`.
    """
    host = host.lower()
    for allowed in allowed_hosts:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False
