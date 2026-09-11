"""
Module 4 — redirect_uri Validation
Tests whether the server properly validates the redirect_uri parameter.
Weak validation allows authorization code theft — complete account takeover.
"""
from urllib.parse import urlparse, urlunparse
from modules.base import BaseModule

EVIL_DOMAIN = "evil.oidcprobe.tld"


def generate_mutations(redirect_uri: str) -> list[tuple[str, str]]:
    """Generate redirect_uri mutations from a legitimate URI."""
    parsed = urlparse(redirect_uri)
    scheme = parsed.scheme
    host = parsed.netloc
    path = parsed.path or "/"
    mutations = []

    # 1. Subdomain confusion
    mutations.append((
        "Subdomain confusion — appended domain",
        f"{scheme}://{host}.{EVIL_DOMAIN}{path}",
    ))
    mutations.append((
        "Subdomain confusion — prepended evil",
        f"{scheme}://{EVIL_DOMAIN}.{host}{path}",
    ))

    # 2. Path traversal
    mutations.append((
        "Path traversal — extra path",
        f"{scheme}://{host}{path}/extra/path",
    ))
    mutations.append((
        "Path traversal — directory escape",
        f"{scheme}://{host}{path}/../../../evil",
    ))

    # 3. Encoded character tricks
    mutations.append((
        "Encoded slash — @evil.com",
        f"{scheme}://{host}%2F@{EVIL_DOMAIN}{path}",
    ))
    mutations.append((
        "Encoded at — URL confusion",
        f"{scheme}://{EVIL_DOMAIN}%40{host}{path}",
    ))
    mutations.append((
        "Backtick confusion",
        f"{scheme}://{host}`{EVIL_DOMAIN}{path}",
    ))

    # 4. Parameter pollution
    mutations.append((
        "Parameter pollution — appended redirect",
        f"{redirect_uri}&redirect_uri=https://{EVIL_DOMAIN}/callback",
    ))
    mutations.append((
        "Parameter pollution — extra question mark",
        f"{redirect_uri}?redirect_uri=https://{EVIL_DOMAIN}/callback",
    ))

    # 5. Open redirect via next/return param on callback
    mutations.append((
        "Open redirect chaining — next param",
        f"{redirect_uri}?next=https://{EVIL_DOMAIN}",
    ))
    mutations.append((
        "Open redirect chaining — return param",
        f"{redirect_uri}?return=https://{EVIL_DOMAIN}",
    ))

    # 6. Scheme variations
    mutations.append((
        "Scheme confusion — HTTP downgrade",
        redirect_uri.replace("https://", "http://"),
    ))
    mutations.append((
        "Localhost loopback",
        f"http://localhost/callback",
    ))
    mutations.append((
        "Wildcard — root domain only",
        f"{scheme}://{'.'.join(host.split('.')[-2:])}/callback",
    ))

    return mutations


class RedirectModule(BaseModule):
    name = "redirect_uri Validation"
    description = "Tests redirect_uri mutations for authorization code theft vectors"

    async def run(self) -> list[dict]:
        findings = []
        redirect_uri = self.config.get("redirect_uri")

        if not redirect_uri:
            return [self.finding(
                title="redirect_uri Validation — Skipped",
                severity="INFO",
                detail="No redirect_uri provided via --redirect-uri. Skipping redirect validation module.",
                recommendation="Provide your app's redirect URI with --redirect-uri to test this module.",
            )]

        endpoint = self.config["target"]
        mutations = generate_mutations(redirect_uri)

        for mutation_name, mutated_uri in mutations:
            params = self._build_params(mutated_uri)
            result = await self.request("GET", endpoint, params=params)

            if not result["ok"]:
                continue

            accepted = self._was_accepted(result, mutated_uri)

            if accepted:
                # Determine severity based on mutation type
                if "confusion" in mutation_name.lower() or "encoded" in mutation_name.lower():
                    severity = "CRITICAL"
                elif "pollution" in mutation_name.lower() or "traversal" in mutation_name.lower():
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                findings.append(self.finding(
                    title=f"Weak redirect_uri Validation — {mutation_name}",
                    severity=severity,
                    detail=(
                        f"The server accepted a manipulated redirect_uri using the '{mutation_name}' technique. "
                        f"An attacker can craft an authorization URL that sends the victim's "
                        f"authorization code to an attacker-controlled endpoint, enabling "
                        f"complete account takeover without the victim's knowledge."
                    ),
                    evidence=(
                        f"Legitimate URI: {redirect_uri} | "
                        f"Accepted mutation: {mutated_uri} | "
                        f"HTTP status: {result['status']}"
                    ),
                    recommendation=(
                        "Implement exact-match validation of redirect_uri against a pre-registered allowlist. "
                        "Never use prefix matching, substring matching, or regex with wildcards. "
                        "Reject any URI that does not exactly match a registered value."
                    ),
                    extras={
                        "mutation": mutation_name,
                        "legitimate_uri": redirect_uri,
                        "accepted_uri": mutated_uri,
                    }
                ))

        if not findings:
            findings.append(self.finding(
                title="redirect_uri Validation Appears Strict",
                severity="INFO",
                detail=f"All {len(mutations)} redirect_uri mutations were rejected. Exact-match validation appears to be in place.",
            ))

        return findings

    def _was_accepted(self, result: dict, mutated_uri: str) -> bool:
        """
        Determine if the server accepted the mutated URI.
        Acceptance signals: no error about redirect_uri, or redirect to the mutated URI.
        """
        body_lower = result["body"].lower()
        redirect_lower = result["redirect_url"].lower()

        # Server explicitly rejected redirect_uri
        rejection_signals = [
            "invalid redirect", "redirect_uri", "invalid_redirect",
            "redirect not allowed", "unauthorized redirect",
        ]
        for signal in rejection_signals:
            if signal in body_lower:
                return False

        # Server redirected to the evil domain
        if EVIL_DOMAIN.lower() in redirect_lower:
            return True

        # Server returned 200 without a redirect_uri error — possibly accepted
        if result["status"] == 200 and not any(s in body_lower for s in rejection_signals):
            return True

        return False

    def _build_params(self, redirect_uri: str) -> dict:
        p = {"redirect_uri": redirect_uri}
        if self.config.get("client_id"):
            p["client_id"] = self.config["client_id"]
        p["response_type"] = "code"
        return p
