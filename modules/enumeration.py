"""
Module 1 — Account Enumeration
Tests whether login_hint leaks account existence via timing,
response size, redirect URL, or error message differences.
"""
import asyncio
from modules.base import BaseModule

TIMING_THRESHOLD_MS = 150   # flag if valid/invalid differ by this much
SIZE_THRESHOLD_BYTES = 100  # flag if response sizes differ by this much

FAKE_EMAIL = "zzz_nonexistent_99999@thisdoesnotexist.tld"
MALFORMED = "malformed@@@@invalid..value"


class EnumerationModule(BaseModule):
    name = "Account Enumeration"
    description = "Tests if login_hint leaks account existence via response differences"

    async def run(self) -> list[dict]:
        findings = []
        valid_email = self.config.get("email")

        if not valid_email:
            return [self.finding(
                title="Account Enumeration — Skipped",
                severity="INFO",
                detail="No valid email provided via --email. Skipping enumeration module.",
                recommendation="Provide a known valid email with --email to test enumeration.",
            )]

        endpoint = self.config["target"]
        params = self._build_params(valid_email)

        # Send each request 3 times and average — reduces noise
        results = {}
        for label, email in [("valid", valid_email), ("fake", FAKE_EMAIL), ("malformed", MALFORMED)]:
            timings = []
            sizes = []
            statuses = []
            redirects = []
            bodies = []

            for _ in range(3):
                r = await self.request("GET", endpoint, params={**params, "login_hint": email})
                if r["ok"]:
                    timings.append(r["elapsed_ms"])
                    sizes.append(r["size"])
                    statuses.append(r["status"])
                    redirects.append(r["redirect_url"])
                    bodies.append(r["body"][:500])
                await asyncio.sleep(0.3)

            if timings:
                results[label] = {
                    "avg_time_ms": round(sum(timings) / len(timings)),
                    "avg_size": round(sum(sizes) / len(sizes)),
                    "status": statuses[0],
                    "redirect": redirects[0],
                    "body_sample": bodies[0],
                }

        if "valid" not in results or "fake" not in results:
            return [self.finding(
                title="Account Enumeration — Could Not Complete",
                severity="INFO",
                detail="Endpoint did not respond correctly to enumeration probes.",
            )]

        v = results["valid"]
        f = results["fake"]

        # Timing diff
        time_diff = abs(v["avg_time_ms"] - f["avg_time_ms"])
        if time_diff >= TIMING_THRESHOLD_MS:
            faster = "valid" if v["avg_time_ms"] < f["avg_time_ms"] else "fake"
            findings.append(self.finding(
                title="Account Enumeration via Timing Difference",
                severity="MEDIUM",
                detail=(
                    f"Response times differ by {time_diff}ms between a valid and fake email. "
                    f"The server responds faster to '{faster}' accounts, suggesting a "
                    f"conditional database lookup — leaking whether an account exists."
                ),
                evidence=(
                    f"Valid email: {v['avg_time_ms']}ms avg | "
                    f"Fake email: {f['avg_time_ms']}ms avg | "
                    f"Difference: {time_diff}ms"
                ),
                recommendation=(
                    "Add a constant-time delay to authentication responses regardless of "
                    "whether the account exists. Never return faster for known accounts."
                ),
            ))

        # Size diff
        size_diff = abs(v["avg_size"] - f["avg_size"])
        if size_diff >= SIZE_THRESHOLD_BYTES:
            findings.append(self.finding(
                title="Account Enumeration via Response Size Difference",
                severity="MEDIUM",
                detail=(
                    f"Response sizes differ by {size_diff} bytes between a valid and fake email. "
                    f"Different content is being rendered — possibly a welcome message, "
                    f"different form, or account-specific UI element."
                ),
                evidence=(
                    f"Valid email: {v['avg_size']:,} bytes | "
                    f"Fake email: {f['avg_size']:,} bytes | "
                    f"Difference: {size_diff:,} bytes"
                ),
                recommendation=(
                    "Return identical response size for known and unknown accounts. "
                    "Use a generic 'enter your credentials' message regardless of account existence."
                ),
            ))

        # Redirect diff
        if v["redirect"] and f["redirect"] and v["redirect"] != f["redirect"]:
            findings.append(self.finding(
                title="Account Enumeration via Redirect URL Difference",
                severity="HIGH",
                detail=(
                    "The server redirects to different URLs for valid vs fake accounts. "
                    "This directly and unambiguously confirms account existence to an attacker."
                ),
                evidence=(
                    f"Valid email redirect: {v['redirect']} | "
                    f"Fake email redirect: {f['redirect']}"
                ),
                recommendation=(
                    "Always redirect to the same URL regardless of whether the account exists. "
                    "Handle the account-not-found case after the redirect, not before."
                ),
            ))

        # Status code diff
        if v["status"] != f["status"]:
            findings.append(self.finding(
                title="Account Enumeration via HTTP Status Code Difference",
                severity="HIGH",
                detail=(
                    f"Server returns HTTP {v['status']} for valid accounts and "
                    f"HTTP {f['status']} for fake accounts. "
                    "Status code differences are the most obvious form of account enumeration."
                ),
                evidence=(
                    f"Valid email: HTTP {v['status']} | "
                    f"Fake email: HTTP {f['status']}"
                ),
                recommendation="Return the same HTTP status code regardless of account existence.",
            ))

        # Error message diff — check if bodies contain different keywords
        valid_body = v["body_sample"].lower()
        fake_body = f["body_sample"].lower()
        leak_phrases = ["not found", "no account", "doesn't exist", "invalid user", "unknown"]
        for phrase in leak_phrases:
            if phrase in fake_body and phrase not in valid_body:
                findings.append(self.finding(
                    title="Account Enumeration via Error Message",
                    severity="HIGH",
                    detail=(
                        f"The server returns a specific error message ('{phrase}') for non-existent "
                        f"accounts but not for valid ones — directly confirming account existence."
                    ),
                    evidence=f"Fake email response contains: '{phrase}'",
                    recommendation=(
                        "Use generic error messages like 'Invalid credentials' for all cases. "
                        "Never reveal whether the username or password was wrong."
                    ),
                ))
                break

        if not findings:
            findings.append(self.finding(
                title="Account Enumeration — No Differences Detected",
                severity="INFO",
                detail="Responses for valid and fake accounts appear identical in timing, size, status, and redirect.",
            ))

        return findings

    def _build_params(self, email: str) -> dict:
        """Build base authorization request parameters."""
        p = {}
        if self.config.get("client_id"):
            p["client_id"] = self.config["client_id"]
        if self.config.get("redirect_uri"):
            p["redirect_uri"] = self.config["redirect_uri"]
        p["response_type"] = "code"
        p["login_hint"] = email
        return p
