import sys
import yaml
import json
import requests
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"


def execute_request(method, url, payload, headers):
    if method.upper() == "GET":
        return requests.get(
            url,
            params=payload,
            headers=headers,
            timeout=5
        )

    return requests.post(
        url,
        json=payload,
        headers=headers,
        timeout=5
    )


def classify_result(expected, direct_response, waf_response, defense):
    direct_status = getattr(direct_response, "status_code", None)
    waf_status = getattr(waf_response, "status_code", None)

    direct_body = getattr(direct_response, "text", "") or ""
    waf_body = getattr(waf_response, "text", "") or ""

    # WAF protection scenarios
    if expected == "waf_block":
        if waf_status in (403, 406, 429):
            return "DEFENSE_SUCCESS_BLOCKED"

        return "WAF_CONTROL_NOT_CONFIRMED"

    # Broken Access Control
    if defense.get("control") == "authorization":
        if waf_status in (401, 403):
            return "CONTROL_ENFORCED"

        if direct_status == 200 and waf_status == 200:
            return "AUTHORIZATION_CONTROL_NOT_CONFIRMED"

        return "REQUIRES_REVIEW"

    # Insecure Design / Business Logic
    if expected == "business_logic":
        normalized_body = direct_body.replace(" ", "")

        if (
            direct_status == 200
            and '"accepted":true' in normalized_body
        ):
            return "BUSINESS_LOGIC_FLAW_OBSERVED"

        if waf_status in (403, 406):
            return "DEFENSE_CONTROL_INTERFERED"

        return "REQUIRES_REVIEW"

    # Vulnerable Components
    if expected == "vulnerable_component":
        if direct_status == 200 and waf_status == 200:
            return "VULNERABLE_COMPONENT_EXPOSED"

        if waf_status in (401, 403):
            return "CONTROL_ENFORCED"

        return "REQUIRES_REVIEW"

    # Authentication / Rate Limiting
    if expected == "rate_limit":
        if waf_status == 429:
            return "RATE_LIMITED"

        return "RATE_LIMIT_NOT_CONFIRMED"

    # Software and Data Integrity
    if expected == "integrity":
        normalized_body = direct_body.replace(" ", "")

        if (
            direct_status == 200
            and '"accepted":true' in normalized_body
        ):
            return "INTEGRITY_VALIDATION_FLAW_OBSERVED"

        return "INTEGRITY_CONTROL_ENFORCED"

    # Logging / Log Injection
    if expected == "log_injection":
        if (
            waf_status == 200
            and '"logged"' in waf_body
        ):
            return "LOG_INJECTION_OBSERVED"

        if waf_status in (400, 403):
            return "LOG_INJECTION_BLOCKED"

        return "REQUIRES_REVIEW"

    # SSRF
    if expected == "ssrf":
        if direct_status == 200 and waf_status == 200:
            return "SSRF_SIMULATION_PROCESSED"

        if waf_status in (401, 403):
            return "SSRF_BLOCKED"

        return "REQUIRES_REVIEW"

    return "REQUIRES_REVIEW"


def run_single_manifest(manifest_path):
    with open(manifest_path, "r") as f:
        data = yaml.safe_load(f)

    scenario = data["scenario"]
    target = data["target"]
    steps = data["steps"]
    expected = data.get("expected")
    defense = data.get("defense", {})

    report_data = {
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "category": scenario["category"],
        "execution_timestamp": datetime.now().isoformat(),
        "expected_behavior": expected,
        "defense": defense,
        "results": []
    }

    print("=" * 50)
    print(
        f"[*] Running: "
        f"{scenario['id']} - {scenario['name']}"
    )
    print(f"[*] Category: {scenario['category']}")
    print("=" * 50)

    direct_base = (
        f"{target['host']}:{target['direct_port']}"
        f"{target['endpoint']}"
    )

    waf_base = (
        f"{target['host']}:{target['waf_port']}"
        f"{target['endpoint']}"
    )

    waf_target = target.get("waf_target")
    headers_base = {}

    if waf_target:
        headers_base["X-WebXploit-Target"] = waf_target

    # Execute every scenario step
    for step in steps:
        method = step.get("method", "POST")
        payload = step.get("payload", {})
        step_headers = step.get("headers", {})

        waf_headers = {
            **step_headers,
            **headers_base
        }

        step_result = {
            "step": step["step"],
            "name": step["name"],
            "payload": payload,
            "direct_app": {},
            "waf_proxy": {}
        }

        direct_response = None
        waf_response = None

        # ---------------------------------------------------------
        # Direct vulnerable application
        # ---------------------------------------------------------
        try:
            direct_response = execute_request(
                method,
                direct_base,
                payload,
                step_headers
            )

            step_result["direct_app"] = {
                "status_code": direct_response.status_code,
                "response_body_preview": direct_response.text[:500]
            }

            print(
                f"    [Direct App] Status: "
                f"{direct_response.status_code}"
            )

        except Exception as e:
            step_result["direct_app"] = {
                "error": str(e)
            }

            print(
                f"    [Direct App] ERROR: {e}"
            )

        # ---------------------------------------------------------
        # WAF protected path
        # ---------------------------------------------------------
        try:
            waf_response = execute_request(
                method,
                waf_base,
                payload,
                waf_headers
            )

            step_result["waf_proxy"] = {
                "status_code": waf_response.status_code,
                "response_body_preview": waf_response.text[:500]
            }

            print(
                f"    [WAF Proxy] Status: "
                f"{waf_response.status_code}"
            )

        except Exception as e:
            step_result["waf_proxy"] = {
                "error": str(e)
            }

            print(
                f"    [WAF Proxy] ERROR: {e}"
            )

        # ---------------------------------------------------------
        # Per-step classification
        # ---------------------------------------------------------
        outcome = classify_result(
            expected,
            direct_response,
            waf_response,
            defense
        )

        step_result["outcome"] = outcome

        print(
            f"    [--> RESULT] {outcome}"
        )
        print("-" * 50)

        report_data["results"].append(step_result)

    # -------------------------------------------------------------
    # Scenario-level evaluation
    # -------------------------------------------------------------

    # A07 is a multi-step rate-limit scenario.
    # The complete scenario is successful if any WAF request
    # receives HTTP 429.
    if expected == "rate_limit":
        waf_statuses = [
            result.get("waf_proxy", {}).get("status_code")
            for result in report_data["results"]
        ]

        if 429 in waf_statuses:
            report_data["scenario_outcome"] = "RATE_LIMITED"
        else:
            report_data["scenario_outcome"] = (
                "RATE_LIMIT_NOT_CONFIRMED"
            )

    else:
        # Single-step scenarios use their recorded outcome.
        outcomes = [
            result.get("outcome")
            for result in report_data["results"]
            if result.get("outcome")
        ]

        report_data["scenario_outcome"] = (
            outcomes[0]
            if outcomes
            else "REQUIRES_REVIEW"
        )

    print(
        f"[+] Scenario Result: "
        f"{report_data['scenario_outcome']}"
    )

    # -------------------------------------------------------------
    # Write evidence report
    # -------------------------------------------------------------
    report_file = (
        REPORTS_DIR /
        f"evidence_{scenario['id']}.json"
    )

    with open(report_file, "w") as f:
        json.dump(
            report_data,
            f,
            indent=2
        )

    print(
        f"[+] Evidence: {report_file}"
    )
    print()


def run_suite(path_arg):
    path = Path(path_arg)

    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if path.is_dir():
        manifest_files = sorted(
            path.glob("*.yaml")
        )

        print(
            f"[+] Found {len(manifest_files)} "
            f"OWASP scenarios in "
            f"'{path}'. Executing full suite...\n"
        )

        for manifest in manifest_files:
            run_single_manifest(manifest)

    elif path.is_file():
        run_single_manifest(path)

    else:
        print(
            f"[!] Invalid path: {path_arg}"
        )
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: "
            "python3 runner.py "
            "<manifest_file_or_directory>"
        )
        sys.exit(1)

    run_suite(sys.argv[1])
