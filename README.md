# WebXploit

**Web Application Attack Simulation & Defense Toolkit — Internship Project**

WebXploit is a local Docker-based cybersecurity lab that demonstrates selected OWASP Top 10 web-application risks through reproducible YAML scenarios. A Python runner executes the scenarios against intentionally vulnerable local targets and then repeats them through **one centralized ModSecurity + OWASP CRS WAF**. Results are saved as evidence for security validation and remediation discussions.

## Architecture

`YAML Scenario → Python Runner → Common WAF :8080 → Lab Target → Evidence / Evaluation`

The runner performs a direct-target comparison and a WAF-protected request. Scenario-specific targets are selected by the internal `X-WebXploit-Target` header; the public lab exposes only one WAF port.

## OWASP coverage

| ID | Scenario | Lab implementation |
|---|---|---|
| A01 | Broken Access Control | Unauthorized admin resource vs authorization-protected target |
| A02 | Cryptographic Failures | Exposed backup/configuration artifact with WAF compensating control |
| A03 | Injection | SQLi authentication-bypass simulation against Juice Shop |
| A04 | Insecure Design | Negative business-logic quantity |
| A05 | Security Misconfiguration | Juice Shop `/ftp` exposure with WAF mitigation |
| A06 | Vulnerable Components | Controlled outdated-component inventory simulation |
| A07 | Authentication Failures | Repeated invalid-login attempts and WAF rate limiting |
| A08 | Data Integrity Failures | Unauthorized role-value acceptance simulation |
| A09 | Logging Failures | CRLF/log-injection simulation with shared telemetry |
| A10 | SSRF | Docker-only mock metadata service; no cloud metadata access |

## Run

```bash
python3 -m pip install -r requirements.txt
bash scripts/validate_project.sh
bash scripts/start_lab.sh
bash scripts/run_all.sh
```

Evidence is written to `reports/runs/`.

## Safety

The project is designed for a local Docker lab. The safe runner rejects non-local HTTP targets and external URLs inside payloads. A10 uses a Docker-only fake metadata service.

## Internship learning outcomes

- OWASP Top 10 mapping and VAPT methodology
- HTTP request automation with Python
- Docker Compose lab design
- ModSecurity / OWASP CRS WAF validation
- Vulnerable vs defensive-path comparison
- Evidence collection and remediation documentation
- Basic security regression testing
