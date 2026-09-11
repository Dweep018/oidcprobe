"""
Module 3 — Parameter Bounds & Log Amplification
Tests whether the server enforces input length limits on login_hint
and username fields. Directly models the Keycloak finding where
~124,000 chars in the username field caused 127x log amplification
from a single unauthenticated request.
"""
import asyncio
from modules.base import BaseModule

# Test lengths — escalating from sane to extreme
TEST_LENGTHS = [255, 1_000, 10_000, 50_000, 124_000]

# Character used for padding — safe, no special meaning
SAFE_CHAR = "a"

# How much slower is acceptable before flagging
SLOWDOWN_THRESHOLD = 3.0

# Response size growth that indicates the value is being reflected/logged
SIZE_GROWTH_THRESHOLD = 5.0


class BoundsModule(BaseModule):
    name = "Parameter Bounds & Log Amplification"
    description = (
        "Tests input length limits on login_hint/username — "
        "detects log amplification and unbounded input acceptance"
    )

    async def run(self) -> list[dict]:
        findings = []
        endpoint = self.config["target"]

        # Baseline with normal input
        baseline_result = await self.request(
            "GET", endpoint,
            params=self._build_params("normal@test.com"),
        )

        if not baseline_result["ok"]:
            # Try POST for login form endpoints
            baseline_result = await self.request(
                "POST", endpoint,
                data={"username": "normal@test.com", "password": "wrong"},
            )

        if not baseline_result["ok"]:
            return [self.finding(
                title="Parameter Bounds — Could Not Establish Baseline",
                severity="INFO",
                detail="Endpoint did not respond to baseline probe. Check --target and --client-id.",
            )]

        baseline_time = baseline_result["elapsed_ms"]
        baseline_size = baseline_result["size"]

        last_accepted_length = 0
        truncation_length = None

        for length in TEST_LENGTHS:
            payload = (SAFE_CHAR * (length - 10)) + "@test.com"  # looks like an email

            # Try GET (login_hint) and POST (username field)
            result_get = await self.request(
                "GET", endpoint,
                params=self._build_params(payload),
            )

            result_post = await self.request(
                "POST", endpoint,
                data={"username": payload, "password": "wrong"},
            )

            # Use whichever responded
            result = result_get if result_get["ok"] else result_post
            method = "GET login_hint" if result_get["ok"] else "POST username"

            if not result["ok"]:
                continue

            slowdown = result["elapsed_ms"] / baseline_time if baseline_time > 0 else 1
            size_growth = result["size"] / baseline_size if baseline_size > 0 else 1

            # Check if value was truncated by looking at reflected content
            if payload[:20] in result["body"] and payload[-20:] not in result["body"]:
                truncation_length = length

            # Check if accepted without error
            accepted = result["status"] in (200, 302) and "error" not in result["body"].lower()[:200]

            if accepted:
                last_accepted_length = length

                # Log amplification finding — the core Keycloak finding
                if length >= 10_000:
                    # Calculate amplification factor
                    # A 124k char value written to logs = ~124KB per request
                    # vs ~34B for a normal username
                    estimated_log_bytes = length  # roughly 1 byte per char in logs
                    normal_log_bytes = 50  # rough normal log entry size for username
                    amplification = round(estimated_log_bytes / normal_log_bytes)

                    severity = "CRITICAL" if length >= 50_000 else "HIGH" if length >= 10_000 else "MEDIUM"

                    findings.append(self.finding(
                        title=f"Log Amplification via Unbounded {method} Input ({length:,} chars accepted)",
                        severity=severity,
                        detail=(
                            f"The server accepted {length:,} characters in the {method} parameter "
                            f"without rejection or truncation. If this value is written to authentication "
                            f"logs (e.g. LOGIN_ERROR events), a single unauthenticated request could "
                            f"generate ~{estimated_log_bytes // 1000}KB of log data — "
                            f"approximately {amplification}x the size of a normal log entry. "
                            f"An attacker sending repeated requests can exhaust disk space."
                        ),
                        evidence=(
                            f"Input length: {length:,} chars | "
                            f"Response time: {result['elapsed_ms']}ms (baseline: {baseline_time}ms) | "
                            f"Response size: {result['size']:,} bytes | "
                            f"HTTP status: {result['status']} | "
                            f"Method: {method}"
                        ),
                        recommendation=(
                            f"Enforce a hard maximum length on all authentication input fields "
                            f"(recommended: 255 characters for username/email). "
                            f"Reject requests exceeding the limit with HTTP 400 before the value "
                            f"reaches the logging layer. Never write unbounded user input to logs."
                        ),
                        extras={
                            "input_length": length,
                            "estimated_log_amplification": f"{amplification}x",
                            "method": method,
                            "response_time_ms": result["elapsed_ms"],
                            "baseline_time_ms": baseline_time,
                        }
                    ))

                    if slowdown >= SLOWDOWN_THRESHOLD:
                        findings.append(self.finding(
                            title=f"Response Slowdown at {length:,} char Input ({slowdown:.1f}x)",
                            severity="MEDIUM",
                            detail=(
                                f"Response time grew {slowdown:.1f}x (from {baseline_time}ms to "
                                f"{result['elapsed_ms']}ms) when sending {length:,} characters. "
                                f"The server is doing proportional work on the input — "
                                f"likely a regex validation, string copy, or database write."
                            ),
                            evidence=f"Baseline: {baseline_time}ms | {length:,} chars: {result['elapsed_ms']}ms | Slowdown: {slowdown:.1f}x",
                            recommendation=(
                                "Reject oversized input before any processing occurs. "
                                "Length check should be the first validation step."
                            ),
                        ))

                    break  # Confirmed vulnerable, stop escalating

            await asyncio.sleep(0.5)  # Be gentle between large requests

        # Report truncation if detected
        if truncation_length:
            findings.append(self.finding(
                title=f"Input Truncated at ~{truncation_length:,} Characters",
                severity="LOW",
                detail=(
                    f"The server appears to truncate input at approximately {truncation_length:,} characters "
                    f"rather than rejecting it. While truncation prevents the largest payloads, "
                    f"it reveals the underlying field size limit and may cause split-validation "
                    f"issues if downstream systems receive a different value than what was validated."
                ),
                evidence=f"Value reflected in response was shorter than the {truncation_length:,} char input",
                recommendation=(
                    "Reject oversized input with HTTP 400 rather than silently truncating. "
                    "Silent truncation can cause split-validation vulnerabilities."
                ),
            ))

        # If nothing large was accepted
        if last_accepted_length < 10_000 and not findings:
            findings.append(self.finding(
                title="Input Length Limits Appear to be Enforced",
                severity="INFO",
                detail=f"Server rejected inputs above ~{last_accepted_length:,} characters. No log amplification risk detected.",
            ))

        return findings

    def _build_params(self, value: str) -> dict:
        p = {"login_hint": value}
        if self.config.get("client_id"):
            p["client_id"] = self.config["client_id"]
        if self.config.get("redirect_uri"):
            p["redirect_uri"] = self.config["redirect_uri"]
        p["response_type"] = "code"
        return p
