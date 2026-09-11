"""
Base Module — Shared request handling and finding formatting.
"""
import httpx


class BaseModule:
    name = "Base Module"
    description = "Base module class"

    def __init__(self, client: httpx.AsyncClient, config: dict):
        self.client = client
        self.config = config

    async def request(self, method: str, url: str, **kwargs) -> dict:
        """Helper method to send requests safely and return formatted results."""
        try:
            response = await self.client.request(method, url, **kwargs)
            return {
                "ok": True,
                "status": response.status_code,
                "body": response.text,
                "headers": dict(response.headers),
                "redirect_url": str(response.next_request.url) if response.next_request else "",
                "elapsed_ms": round(response.elapsed.total_seconds() * 1000),
                "size": len(response.content),
            }
        except Exception as e:
            return {
                "ok": False,
                "status": 0,
                "body": "",
                "headers": {},
                "redirect_url": "",
                "elapsed_ms": 0,
                "size": 0,
                "error": str(e),
            }

    def finding(
        self,
        title: str,
        severity: str,
        detail: str,
        evidence: str = "",
        recommendation: str = "",
        extras: dict = None,
    ) -> dict:
        """Format a standardized finding dictionary."""
        return {
            "title": title,
            "severity": severity,
            "module": self.name,
            "detail": detail,
            "evidence": evidence,
            "recommendation": recommendation,
            "extras": extras or {},
        }
