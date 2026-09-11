# oidcprobe — OIDC/OAuth2 Parameter Hardening Verification Tool

Automatically verifies that OIDC/OAuth2 endpoints enforce input bounds on parameters like `login_hint`, `username`, and `redirect_uri` — before an attacker tests them for you.

---

## Modules

| Module | Flag | What it tests |
|---|---|---|
| Account Enumeration | `enumeration` | Timing, size, redirect, and error message differences for valid vs fake accounts |
| Input Sanitization | `sanitization` | XSS, CRLF injection (CWE-93), ANSI escape sequences (CWE-117), null byte injection via `login_hint` |
| Parameter Bounds | `bounds` | Input length limits, log amplification (>10x to 127x via CWE-400), response time growth at 255 → 124,000 chars |
| redirect_uri Validation | `redirect` | 14 `redirect_uri` mutations covering subdomain confusion, path traversal, encoded tricks, parameter pollution |

---

## Installation

```bash
git clone [https://github.com/Dweep018/oidcprobe](https://github.com/Dweep018/oidcprobe)
cd oidcprobe
pip install -r requirements.txt

---

## Usage

# Full scan
python oidcprobe.py --target https://<target>/authorize --client-id myclient

# With known valid email (enables enumeration module)
python oidcprobe.py --target https://<target>/authorize --client-id myclient --email user@company.com

# With redirect URI (enables redirect_uri validation)
python oidcprobe.py --target https://<target>/authorize \
  --client-id myclient \
  --redirect-uri [https://app.example.com/callback](https://app.example.com/callback)

# Full scan with all options
python oidcprobe.py --target https://<target>/authorize \
  --client-id myclient \
  --redirect-uri [https://app.example.com/callback](https://app.example.com/callback) \
  --email user@company.com \
  -o report.json

# Specific modules only
python oidcprobe.py --target https://<target>/authorize --modules bounds sanitization

# Authenticated scan
python oidcprobe.py --target https://<target>/authorize -t YOUR_TOKEN

# Custom headers
python oidcprobe.py --target https://<target>/authorize -H "X-Custom: value"

---

## Severity Scoring

| Severity | Examples |
|---|---|
| CRITICAL | Null byte → XSS, redirect_uri subdomain confusion accepted |
| HIGH | Reflected XSS, CRLF header injection, redirect_uri parameter pollution, account enumeration via status code |
| MEDIUM | Account enumeration via timing/size, log amplification at 10,000+ chars, response slowdown |
| LOW | ANSI escape injection, truncation instead of rejection, minor redirect variations |

---

## Output

### Terminal
Live findings per module as confirmed, with severity, evidence string, and fix recommendation.

### JSON Report (`-o report.json`)
```json
{
  "scanner": "oidcprobe",
  "target": "https://<target>/authorize",
  "summary": {
    "overall_risk": "HIGH",
    "total_findings": 3,
    "by_severity": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 2 }
  },
  "findings": [...]
}
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No HIGH/CRITICAL findings |
| `1` | HIGH severity findings found |
| `2` | CRITICAL severity findings found |

---

## Real-World Background

`oidcprobe` originates from original security research disclosed via Keycloak's bug bounty program on **YesWeHack** (awarded 3 reputation points), focusing on pre-authentication parameter hardening across identity protocol layers. 

Core maintainers opened six dedicated upstream tracking issues based on these findings:

* **[#50903](https://github.com/keycloak/keycloak/issues/50903):** Uncontrolled Resource Consumption (CWE-400) where ~124,000 characters in the username field caused 127x log amplification per unauthenticated request (fixed in Keycloak 26.8.0).
* **[#46736](https://github.com/keycloak/keycloak/issues/46736) & [#46740](https://github.com/keycloak/keycloak/issues/46740):** CRLF Injection (CWE-93) and audit log forgery via unvalidated parameters like `kc_idp_hint`.
* **[#47681](https://github.com/keycloak/keycloak/issues/47681) & [#46747](https://github.com/keycloak/keycloak/issues/46747):** ANSI Control Sequence Injection (CWE-117) enabling visual log tampering and forensic evasion.
* **[#40857](https://github.com/keycloak/keycloak/issues/40857):** Session cookie (`KC_RESTART`) header size overflow inducing authentication loop denial-of-service.

`oidcprobe` automates the detection of these exact vulnerability classes across any OIDC/OAuth2 provider.
---

## Roadmap

- [ ] PKCE downgrade detection
- [ ] state parameter CSRF testing
- [ ] Token endpoint parameter fuzzing
- [ ] Provider fingerprinting (Keycloak, Auth0, Okta, Azure AD)
- [ ] HTML report output

---

## License

MIT

## Responsible Use

This tool is for authorized security testing and hardening verification only. Always obtain permission before testing any target.
