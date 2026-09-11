"""JSON report generator."""
from datetime import datetime, timezone


def generate_json_report(config: dict, findings: list, elapsed: float, modules: list) -> dict:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 9))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    overall = "NONE"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev] > 0:
            overall = sev
            break

    return {
        "scanner": "oidcprobe — OIDC/OAuth2 Parameter Hardening Verification Tool",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": config["target"],
        "scan_duration_seconds": round(elapsed, 2),
        "modules_run": modules,
        "summary": {
            "overall_risk": overall,
            "total_findings": len([f for f in findings if f.get("severity") != "INFO"]),
            "by_severity": counts,
        },
        "findings": sorted_findings,
    }
