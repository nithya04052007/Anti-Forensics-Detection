"""
Forensic Logger and Presentation Utility
Provides formatted, colorized DFIR console output for scans, findings, and feature vectors.
"""

import sys
from typing import List, Dict, Any, Optional

# Attempt colorama import for cross-platform ANSI color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _EmptyColor:
        def __getattr__(self, name):
            return ""

    Fore = _EmptyColor()
    Style = _EmptyColor()

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


class ForensicLogger:
    @staticmethod
    def header(text: str) -> None:
        line = "=" * 70
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{line}")
        print(f" {text}")
        print(f"{line}{Style.RESET_ALL}")

    @staticmethod
    def subheader(text: str) -> None:
        print(f"\n{Fore.CYAN}[+] {Style.BRIGHT}{text}{Style.RESET_ALL}")

    @staticmethod
    def info(msg: str) -> None:
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

    @staticmethod
    def success(msg: str) -> None:
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} {msg}")

    @staticmethod
    def warning(msg: str) -> None:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    @staticmethod
    def alert(msg: str) -> None:
        print(f"{Fore.RED}{Style.BRIGHT}[ALERT]{Style.RESET_ALL} {msg}")

    @staticmethod
    def finding(severity: str, category: str, title: str, artifact: str) -> None:
        sev_color = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.MAGENTA + Style.BRIGHT,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.BLUE,
            "INFO": Fore.WHITE
        }.get(severity.upper(), Fore.WHITE)

        print(f"  {sev_color}[{severity.upper()}]{Style.RESET_ALL} ({category}) {Style.BRIGHT}{title}{Style.RESET_ALL}")
        if artifact:
            print(f"    Target: {Fore.CYAN}{artifact}{Style.RESET_ALL}")

    @staticmethod
    def print_findings_summary(findings: List[Dict[str, Any]]) -> None:
        """Display a formatted summary table of findings."""
        if not findings:
            print(f"\n{Fore.GREEN}[OK] No anti-forensic anomalies detected.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.YELLOW}{Style.BRIGHT}=== FORENSIC ANOMALY FINDINGS ({len(findings)}) ==={Style.RESET_ALL}")

        table_data = []
        for f in findings:
            sev = f.get("severity", "INFO")
            cat = f.get("category", "")
            title = f.get("title", "")
            artifact = f.get("artifact_path", "")
            if len(artifact) > 40:
                artifact = "..." + artifact[-37:]
            table_data.append([sev, cat, title, artifact])

        if HAS_TABULATE:
            print(tabulate(table_data, headers=["Severity", "Category", "Anomaly Title", "Artifact Target"], tablefmt="grid"))
        else:
            for row in table_data:
                print(f"  [{row[0]}] [{row[1]}] {row[2]} -> {row[3]}")

    @staticmethod
    def print_features_summary(features: Dict[str, Any], risk_score: float) -> None:
        """Display feature vector and composite threat score."""
        risk_color = Fore.GREEN
        if risk_score >= 70:
            risk_color = Fore.RED + Style.BRIGHT
        elif risk_score >= 40:
            risk_color = Fore.YELLOW + Style.BRIGHT

        print(f"\n{Fore.CYAN}--- Extracted Anti-Forensics Feature Matrix (ML-Ready) ---{Style.RESET_ALL}")
        print(f"Composite Anti-Forensics Risk Score: {risk_color}{risk_score:.2f} / 100.0{Style.RESET_ALL}\n")

        feature_items = list(features.items())
        table_rows = []
        for name, val in sorted(feature_items):
            val_str = f"{val:.4f}" if isinstance(val, float) else str(val)
            table_rows.append([name, val_str])

        if HAS_TABULATE:
            print(tabulate(table_rows, headers=["Feature Name", "Value"], tablefmt="simple"))
        else:
            for k, v in table_rows:
                print(f"  {k:<35} : {v}")
