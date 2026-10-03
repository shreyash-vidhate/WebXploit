# WebXploit Project Status

The internship build uses one centralized ModSecurity/OWASP CRS WAF on `127.0.0.1:8080`. Ten OWASP scenario manifests use the same WAF entry point; the runner selects the intended internal lab target through a scenario header.

## Current design
- OWASP A01–A10 scenario coverage
- Direct vulnerable-path comparison
- Central WAF validation
- Local-only safe runner
- JSON evidence bundles
- Remediation playbook
- Pytest regression checks
- GitHub Actions validation workflow

## Important interpretation
A scenario result is not automatically considered a vulnerability merely because an HTTP request succeeds. The runner records the observed behavior and labels results such as `WAF_BLOCKED`, `CONTROL_ENFORCED`, `RATE_LIMITED`, `LOG_INJECTION_OBSERVED`, or `REQUIRES_REVIEW`.
