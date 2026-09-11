#!/usr/bin/env python3
"""
oidcprobe — OIDC/OAuth2 Parameter Hardening Verification Tool
Automatically verifies that OIDC endpoints enforce input bounds on
parameters like login_hint, username, and redirect_uri — before
an attacker tests them for you.
"""

import argparse
import asyncio
import json
import sys
import time

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box
from rich.text import Text

from modules import EnumerationModule, SanitizationModule, BoundsModule, RedirectModule
from reports import generate_json_report

console = Console()

BANNER = """[bold cyan]
  ██████  ██╗██████╗  ██████ ██████  ██████   ██████  ██████  ███████ 
 ██    ██ ██║██   ██ ██      ██   ██ ██   ██ ██    ██ ██   ██ ██      
 ██    ██ ██║██   ██ ██      ██████  ██████  ██    ██ ██████  █████   
 ██    ██ ██║██   ██ ██      ██      ██   ██ ██    ██ ██   ██ ██      
  ██████  ██║██████   ██████ ██      ██   ██  ██████  ██████  ███████ 
[/bold cyan][dim]  OIDC/OAuth2 Parameter Hardening Verification Tool[/dim]
"""

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️ ",
}

MODULE_MAP = {
    "enumeration": EnumerationModule,
    "sanitization": SanitizationModule,
    "bounds": BoundsModule,
    "redirect": RedirectModule,
}


def print_finding(f: dict):
    sev = f.get("severity", "INFO")
    color = SEVERITY_COLORS.get(sev, "white")
    icon = SEVERITY_ICONS.get(sev, "•")

    console.print(Text.assemble(
        (f"{icon} [{sev}] ", color),
        (f["title"], "bold white"),
    ))
    console.print(f"  [dim]Module:[/dim]  {f['module']}")
    console.print(f"  [dim]Detail:[/dim]  {f['detail']}")
    if f.get("evidence"):
        console.print(f"  [dim]Evidence:[/dim] {f['evidence'][:150]}")
    if f.get("recommendation"):
        console.print(f"  [dim]Fix:[/dim]     [italic]{f['recommendation']}[/italic]")
    console.print()


def print_summary(findings: list, target: str, elapsed: float):
    console.print(Rule("[bold]Scan Summary[/bold]"))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    table = Table(box=box.ROUNDED, header_style="bold dim")
    table.add_column("Target", style="cyan")
    table.add_column("Critical", style="bold red", justify="center")
    table.add_column("High", style="red", justify="center")
    table.add_column("Medium", style="yellow", justify="center")
    table.add_column("Low", style="cyan", justify="center")
    table.add_column("Duration", justify="right")

    table.add_row(
        target,
        str(counts["CRITICAL"]),
        str(counts["HIGH"]),
        str(counts["MEDIUM"]),
        str(counts["LOW"]),
        f"{elapsed:.1f}s",
    )
    console.print(table)


async def main():
    parser = argparse.ArgumentParser(
        prog="oidcprobe",
        description="OIDC/OAuth2 Parameter Hardening Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan
  python oidcprobe.py --target https://<target>/authorize --client-id myclient

  # With known valid email for enumeration testing
  python oidcprobe.py --target https://<target>/authorize --client-id myclient --email user@company.com

  # With redirect URI for redirect_uri validation
  python oidcprobe.py --target https://<target>/authorize --client-id myclient --redirect-uri https://app.example.com/callback

  # Run specific modules only
  python oidcprobe.py --target https://<target>/authorize --modules bounds sanitization

  # Save JSON report
  python oidcprobe.py --target https://<target>/authorize --client-id myclient -o report.json

  # Authenticated scan
  python oidcprobe.py --target https://<target>/authorize -t YOUR_TOKEN
        """,
    )
    parser.add_argument("--target", required=True, help="OIDC authorization endpoint URL")
    parser.add_argument("--client-id", help="OAuth2 client_id for building valid requests")
    parser.add_argument("--redirect-uri", help="Legitimate redirect_uri (required for redirect module)")
    parser.add_argument("--email", help="Known valid email for enumeration testing")
    parser.add_argument("-t", "--token", help="Bearer token for Authorization header")
    parser.add_argument("-H", "--header", action="append", metavar="KEY:VALUE", help="Extra headers")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20)")
    parser.add_argument(
        "--modules", nargs="+",
        choices=["enumeration", "sanitization", "bounds", "redirect"],
        default=["enumeration", "sanitization", "bounds", "redirect"],
        help="Modules to run (default: all)",
    )
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("--no-banner", action="store_true")

    args = parser.parse_args()

    if not args.no_banner:
        console.print(BANNER)

    config = {
        "target": args.target,
        "client_id": args.client_id,
        "redirect_uri": args.redirect_uri,
        "email": args.email,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    console.print(Panel(
        f"[bold white]Target:[/bold white]       [cyan]{args.target}[/cyan]\n"
        f"[bold white]Client ID:[/bold white]    {args.client_id or '[dim]not provided[/dim]'}\n"
        f"[bold white]Redirect URI:[/bold white] {args.redirect_uri or '[dim]not provided[/dim]'}\n"
        f"[bold white]Test email:[/bold white]   {args.email or '[dim]not provided[/dim]'}\n"
        f"[bold white]Modules:[/bold white]      {', '.join(args.modules)}\n"
        f"[bold white]Timeout:[/bold white]      {args.timeout}s",
        title="[bold]Scan Configuration[/bold]",
        border_style="dim",
    ))

    modules_to_run = [MODULE_MAP[m] for m in args.modules]
    all_findings = []

    start = time.monotonic()

    async with httpx.AsyncClient(
        headers=headers,
        timeout=args.timeout,
        verify=False,
        follow_redirects=False,
    ) as client:
        for ModuleClass in modules_to_run:
            mod = ModuleClass(client, config)
            console.print(f"\n[bold dim]▶ Running:[/bold dim] [white]{mod.name}[/white]")
            try:
                findings = await mod.run()
                for f in findings:
                    all_findings.append(f)
                    if f.get("severity") != "INFO":
                        print_finding(f)
                    else:
                        console.print(f"  [dim]{SEVERITY_ICONS['INFO']} {f['detail']}[/dim]\n")
            except Exception as e:
                console.print(f"  [red]✗ Module error: {e}[/red]\n")

    elapsed = time.monotonic() - start
    print_summary(all_findings, args.target, elapsed)

    if args.output:
        report = generate_json_report(config, all_findings, elapsed, args.modules)
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        console.print(f"\n[green]✓ JSON report saved to:[/green] [bold]{args.output}[/bold]")

    severities = {f.get("severity") for f in all_findings}
    if "CRITICAL" in severities:
        sys.exit(2)
    elif "HIGH" in severities:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
