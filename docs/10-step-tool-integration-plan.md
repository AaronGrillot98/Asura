# Asura 90-Tool Integration Plan

Asura should become a serious authorized security orchestration workstation, not a loose launcher and not a claim to replace human pentesters. The product goal is to make trusted tools work harmoniously through scoped execution, normalized evidence, finding correlation, attack-path reasoning, detection mapping, and professional reporting.

## 1. Lock The Core Engine

Keep these first 10 as the default engine:

1. Nmap
2. Nuclei
3. Semgrep
4. Trivy
5. Gitleaks
6. OSV-Scanner
7. Checkov
8. OWASP ZAP
9. Syft
10. Grype

Implementation standard:

- First-class runner for each tool.
- JSON, SARIF, XML, or stable text parser.
- Evidence object for every normalized finding.
- Scanner health and raw log storage.
- Passive, active, and lab mode rules.
- Docker execution profile where practical.
- Report export support.

These tools form the base loop: discover assets, scan code and dependencies, inspect containers and IaC, test web apps, store evidence, and produce prioritized remediation.

## 2. Build The Registry Contract

Every tool must live in `backend/registry/tools.yaml` before it can appear in the UI.

The executable contract is enforced in code and documented in `docs/registry-contract.md`.

Required metadata:

- Tool id and display name
- Pack and category
- Execution class: `core_runner`, `optional_pack`, `reference`, or `blocked`
- Safety modes: `passive`, `active`, `lab`
- Install status and executable name
- Parser/importer status
- Input types and output formats
- Docker availability
- Supported OS
- Command templates
- Recommended use
- Risk warning

Registry acceptance rule:

- A tool can be cataloged with no runner.
- A tool cannot execute until it has mode gating, scope checks, logs, and evidence storage.
- Lab or exploit-validation tools must default to non-destructive settings.
- Blocked tools never receive command templates.

## 3. Expand AppSec And Dependency Coverage

Add tools 11-20 as first-class code and dependency integrations:

11. CodeQL
12. Bandit
13. pip-audit
14. npm audit
15. cargo-audit
16. govulncheck
17. gosec
18. Brakeman
19. ESLint security plugins
20. Bearer

Implementation status: registered as passive runner integrations in `backend/registry/tools.yaml`.

Workflow:

- Run language-specific tools after repo ingestion.
- Normalize to code findings with file, line, rule id, confidence, CWE/OWASP mapping where available.
- Merge duplicate dependency findings across Trivy, OSV-Scanner, Grype, npm audit, pip-audit, cargo-audit, and govulncheck.
- Export and import SARIF where available.
- Feed code findings into attack-path correlation with web and infrastructure findings.

Primary UI additions:

- Code Risk view
- Dependency Risk view
- SARIF import/export
- Duplicate cluster drawer

## 4. Build The Recon Pipeline

Add tools 21-35:

21. Subfinder
22. Amass
23. httpx
24. Naabu
25. dnsx
26. Katana
27. Gau
28. Waybackurls
29. Hakrawler
30. Wappalyzer CLI / webanalyze
31. WhatWeb
32. Wafw00f
33. tlsx
34. shuffledns
35. Assetfinder

Implementation status: registered as scoped recon runner integrations in `backend/registry/tools.yaml`.

Workflow:

- Passive recon: Subfinder, Amass passive, Gau, Waybackurls, Assetfinder.
- Scoped active recon: Naabu, httpx, dnsx, Katana, Hakrawler, tlsx, Wafw00f, WhatWeb, webanalyze.
- Asset graph output: domains, subdomains, hosts, ports, URLs, technologies, TLS certs, WAF status.
- Feed URLs and live services into Nuclei, ZAP, FFUF, Feroxbuster, Dirsearch, Arjun, and API scanners.

Safety controls:

- Passive mode must not touch target infrastructure directly.
- Active probing requires explicit scope.
- Rate limits and concurrency caps are mandatory.
- Active recon entries are marked scope-required and carry risk warnings in the registry contract.

## 5. Add Web Discovery And Vulnerability Depth

Add tools 36-50:

36. FFUF
37. Feroxbuster
38. Gobuster
39. Dirsearch
40. Arjun
41. Nikto
42. Wapiti
43. Dalfox
44. Kxss
45. LinkFinder
46. SecretFinder
47. Retire.js
48. Corsy
49. CRLFuzz
50. OpenRedireX

Workflow:

- Content discovery uses FFUF, Feroxbuster, Gobuster, and Dirsearch.
- Parameter discovery uses Arjun and Kxss.
- JavaScript analysis uses LinkFinder, SecretFinder, and Retire.js.
- Targeted web validation uses Nikto, Wapiti, Dalfox, Corsy, CRLFuzz, and OpenRedireX.
- ZAP and Nuclei remain the main web scanning anchors.

Correlation examples:

- Hidden admin route from FFUF plus weak auth finding from Semgrep.
- Old JavaScript library from Retire.js plus exposed route from Katana.
- CORS issue from Corsy plus leaked token from Gitleaks or TruffleHog.

Safety controls:

- Fuzzers require active mode.
- XSS, CRLF, and redirect validators require authorization and conservative payloads.

## 6. Build API Security As A First-Class Surface

Add tools and importers 51-59:

51. Schemathesis
52. Kiterunner
53. JWT Tool
54. GraphQL Voyager
55. InQL
56. GraphQL Cop
57. Postman collection importer
58. OpenAPI parser
59. RESTler

Workflow:

- Import OpenAPI specs, Postman collections, and GraphQL schemas.
- Build an API inventory: methods, paths, auth expectations, parameters, schemas, risky endpoints.
- Run Schemathesis for schema-driven testing.
- Use Kiterunner for API route discovery in active mode.
- Use JWT Tool as an analyzer for claims, algorithms, expiry, and known misconfigurations.
- Use GraphQL Voyager, InQL, and GraphQL Cop for GraphQL mapping and checks.
- Keep RESTler in lab or explicitly authorized mode.

UI additions:

- API Attack Surface view
- Auth assumption matrix
- Endpoint risk table
- Schema diff viewer

## 7. Strengthen Secrets And Verification Workflows

Add tools 60-63:

60. TruffleHog
61. detect-secrets
62. Whispers
63. Yelp detect-secrets baseline support

Workflow:

- Gitleaks remains the default first pass.
- TruffleHog provides deeper secret detection and optional verification.
- detect-secrets supports baseline workflows for teams.
- Whispers adds config and source-code secret checks.
- Secret findings must include file, line, rule, entropy signal, verification state, and rotation guidance.

Safety controls:

- Verification is opt-in.
- Verification must never mutate accounts or attempt privilege escalation.
- Fake-secret demo mode should be available for safe demos.

## 8. Add Cloud, IaC, And Kubernetes Posture

Add tools 64-77:

64. KICS
65. Terrascan
66. tfsec-compatible rules
67. Cloudsplaining
68. Prowler
69. ScoutSuite
70. Steampipe
71. Parliament
72. cfn-nag
73. kube-score
74. kube-bench
75. Kubescape
76. Polaris
77. Docker Bench for Security

Workflow:

- Checkov and Trivy config stay as anchors.
- KICS and Terrascan add IaC coverage.
- tfsec-compatible rules are treated as parser/rule compatibility.
- Cloudsplaining and Parliament analyze AWS IAM risk.
- Prowler and ScoutSuite handle cloud posture.
- Steampipe is a query/integration layer, not a default scanner.
- kube-score, kube-bench, Kubescape, and Polaris cover Kubernetes posture.
- Docker Bench covers host and daemon checks.

UI additions:

- Cloud posture board
- IAM privilege graph
- Kubernetes risk view
- IaC drift and misconfiguration clusters

Safety controls:

- Cloud integrations require read-only credentials.
- Credential use must be audited.
- Cloud and Kubernetes scans must show account, cluster, namespace, and scope.

## 9. Add Detection Engineering And DFIR

Add tools 78-89:

78. Falco
79. Sigma
80. YARA
81. Suricata rules
82. Zeek
83. OSQuery
84. Chainsaw
85. Hayabusa
86. Velociraptor
87. Volatility 3
88. Plaso/log2timeline
89. Timesketch

Workflow:

- For each finding, ask: can this be detected?
- Sigma maps findings to SIEM-ready detection ideas.
- YARA covers file and malware-pattern detection.
- Suricata and Zeek cover network detection and analysis.
- Falco covers runtime Kubernetes/container signals.
- OSQuery and Velociraptor support endpoint visibility and response workflows.
- Chainsaw and Hayabusa analyze Windows event logs.
- Volatility 3, Plaso/log2timeline, and Timesketch support DFIR import and timeline analysis.

UI additions:

- Detection coverage matrix
- ATT&CK mapping
- Evidence-to-detection drawer
- Timeline import view
- DFIR artifact vault

Safety controls:

- DFIR tooling should primarily import and analyze artifacts.
- Endpoint collection integrations require explicit credentials and audit logging.

## 10. Add AI Security And Harmonized Orchestration

Add tool 90 and prepare the next pack:

90. Garak

Next after 90:

- PyRIT
- MobSF
- JADX
- apktool
- Androguard
- Frida
- Objection
- CyberChef
- Ghidra
- Radare2

Workflow:

- Garak starts the LLM and AI Security Pack.
- Add model endpoint inventory, prompt test suites, RAG exposure checks, prompt leakage checks, and insecure agent tool-use checks.
- PyRIT should follow as a broader generative-AI red-team framework.
- Mobile and reverse-engineering tools should be optional or reference-first until sandboxing and artifact handling are mature.

Harmonization layer:

- Every tool output becomes one of: asset, evidence, finding, attack-path edge, detection rule, remediation task, report section.
- The Correlation Agent links findings across repos, APIs, hosts, containers, cloud, identities, and detections.
- The Remediation Agent orders fixes by exploitability, asset criticality, confidence, and blast radius.
- The Report Agent exports manager-readable and engineer-actionable reports.

Final product standard:

- Asura is not a menu of tools.
- Asura is the system that decides what to run, runs it safely, parses evidence, correlates results, and tells the operator what matters.
