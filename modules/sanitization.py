"""
Module 2 — Input Sanitization
Tests login_hint and username field for XSS, CRLF injection,
ANSI escape sequences, and null byte injection.
"""
from modules.base import BaseModule

PAYLOADS = {
    "XSS — Basic script tag": '"><script>alert(1)</script>',
    "XSS — IMG onerror": '"><img src=x onerror=alert(1)>',
    "XSS — SVG onload": "<svg onload=alert(1)>",
    "XSS — javascript URI": "javascript:alert(1)",
    "CRLF — Cookie injection": "test%0d%0aSet-Cookie:injected=oidcprobe",
    "CRLF — Header injection": "test%0d%0aX-Injected:oidcprobe",
    "CRLF — Response splitting": "test%0d%0a%0d%0a<html>injected</html>",
    "ANSI — Color escape": "\x1b[31mINJECTED\x1b[0m",
    "ANSI — Clear screen": "\x1b[2J",
    "ANSI — Cursor manipulation": "\x1b[1A\x1b[2K",
    "Null byte — truncation probe": "valid@test.com\x00<script>alert(1)</script>",
    "Null byte — path traversal": "valid\x00/../../../etc/passwd",
}

# Unencoded versions to check in response
XSS_MARKERS = ["<script>", "onerror=", "onload=", "javascript:"]
CRLF_MARKERS = ["injected=oidcprobe", "x-injected: oidcprobe", "injected</html>"]
ANSI_MARKERS = ["\x1b[31m", "\x1b[2J", "\x1b[1A"]


class SanitizationModule(BaseModule):
    name = "Input Sanitization"
    description = "Tests for XSS, CRLF, ANSI escape, and null byte injection via login_hint"

    async def run(self) -> list[dict]:
        findings = []
        endpoint = self.config["target"]
        params = self._build_params()

        for payload_name, payload in PAYLOADS.items():
            result = await self.request(
                "GET", endpoint,
                params={**params, "login_hint": payload},
            )

            if not result["ok"]:
                continue

            body = result["body"]
            headers = {k.lower(): v.lower() for k, v in result["headers"].items()}
            payload_type = payload_name.split(" — ")[0]

            # XSS check — payload appears unencoded in body
            if payload_type == "XSS":
                for marker in XSS_MARKERS:
                    if marker.lower() in body.lower():
                        findings.append(self.finding(
                            title=f"Reflected XSS via login_hint — {payload_name}",
                            severity="HIGH",
                            detail=(
                                f"The payload '{payload_name}' was reflected verbatim in the response body "
                                f"without HTML encoding. This is a reflected XSS vulnerability in an "
                                f"authentication flow — no user interaction beyond clicking a crafted URL."
                            ),
                            evidence=f"Marker '{marker}' found unencoded in response body",
                            recommendation=(
                                "HTML-encode all user-controlled values before reflecting them in responses. "
                                "Apply output encoding at every point the value touches the DOM."
                            ),
                        ))
                        break

            # CRLF check — injected value appears in headers or body
            elif payload_type == "CRLF":
                for marker in CRLF_MARKERS:
                    if marker in headers.get("set-cookie", "") or \
                       marker in headers.get("x-injected", "") or \
                       marker in body.lower():
                        findings.append(self.finding(
                            title=f"CRLF Injection via login_hint — {payload_name}",
                            severity="HIGH",
                            detail=(
                                "CRLF sequences in login_hint are reflected into HTTP response headers. "
                                "This enables HTTP response splitting, cookie injection, and "
                                "cache poisoning attacks."
                            ),
                            evidence=f"Injected marker found in response: '{marker}'",
                            recommendation=(
                                "Strip or reject CR (\\r) and LF (\\n) characters from all "
                                "user-controlled input before using them in HTTP headers."
                            ),
                        ))
                        break

            # ANSI check — escape sequences in body
            elif payload_type == "ANSI":
                for marker in ANSI_MARKERS:
                    if marker in body:
                        findings.append(self.finding(
                            title=f"ANSI Escape Injection via login_hint — {payload_name}",
                            severity="LOW",
                            detail=(
                                "ANSI escape sequences in login_hint are reflected into the response. "
                                "If this value is also written to server logs (likely in an auth error), "
                                "it can manipulate terminal output for developers viewing logs — "
                                "hiding malicious entries or altering displayed content."
                            ),
                            evidence=f"ANSI escape sequence found unstripped in response body",
                            recommendation=(
                                "Strip ANSI escape sequences (\\x1b[...m) from all user input "
                                "before logging or reflecting. Use a sanitization library."
                            ),
                        ))
                        break

            # Null byte — server error or unexpected behavior
            elif payload_type == "Null byte":
                if result["status"] == 500:
                    findings.append(self.finding(
                        title="Null Byte Causes Server Error in login_hint",
                        severity="MEDIUM",
                        detail=(
                            "Sending a null byte (\\x00) in login_hint caused an HTTP 500 error. "
                            "This indicates the server passes the value to a system that cannot "
                            "handle null bytes — likely a C library, database, or file system call."
                        ),
                        evidence=f"HTTP 500 triggered by payload: {payload_name}",
                        recommendation=(
                            "Validate and sanitize input to reject null bytes before passing "
                            "to downstream systems. Return HTTP 400 for invalid input."
                        ),
                    ))
                elif result["status"] == 200 and "<script>" in body.lower():
                    findings.append(self.finding(
                        title="Null Byte Truncation Leads to XSS",
                        severity="CRITICAL",
                        detail=(
                            "The server truncated the value at the null byte, validating only "
                            "the safe prefix, but the downstream system processed the full value "
                            "including the XSS payload after the null byte."
                        ),
                        evidence="XSS payload after null byte reflected in response",
                        recommendation=(
                            "Reject any input containing null bytes at the earliest validation point. "
                            "Never pass null-byte-containing strings to downstream systems."
                        ),
                    ))

        return findings

    def _build_params(self) -> dict:
        p = {}
        if self.config.get("client_id"):
            p["client_id"] = self.config["client_id"]
        if self.config.get("redirect_uri"):
            p["redirect_uri"] = self.config["redirect_uri"]
        p["response_type"] = "code"
        return p
