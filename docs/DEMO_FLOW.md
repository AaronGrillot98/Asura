# Demo Flow

1. Open the Command Center at <http://localhost:3000>. The demo banner reads
   "findings on this dashboard are seeded demo evidence."
2. Review the **Acme FlightOps Demo** project scope on `/projects/demo`.
3. Inspect the seeded findings on `/findings`:
   - Privileged API token committed to repository (gitleaks)
   - Vulnerable npm dependency (osv-scanner)
   - Missing auth check on internal route (semgrep)
   - Exposed admin route on public host (nuclei)
   - Weak CORS policy (zap)
   - Container image vulnerable OpenSSL (trivy)
   - Overbroad IAM policy (checkov)
   - Missing security headers (zap)
   - Old TLS / weak cipher (nmap)
   - API endpoint without rate limit (zap)
4. Open the Arsenal at `/arsenal` and filter by tag or risk level.
5. Open `/attack-paths` and review the three correlated hypotheses:
   - Potential account takeover chain
   - Container-to-service exposure chain
   - Cloud permission risk chain
6. Export a Markdown or JSON report from `/reports`.
7. Visit `/audit` to confirm every scope decision was recorded.

No live vulnerable target is required to browse the demo content. When
you're ready to run real scans against authorized targets, just install
the scanner (e.g. `pipx install semgrep`) and click "Run scan" on the
Command Center — real execution is the default. Set
`ASURA_DEMO_MODE=1` to freeze every scan on seeded output (useful for
screenshots and air-gapped review).
