#!/usr/bin/env python3
import logging
from rich.console import Console
from rich.table import Table

from config_loader import load_config
from alert_parser import AlertParser

config = load_config()
console = Console()
logging.basicConfig(
    level=config["logging"]["level"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename=config["logging"]["file"],
)

SEVERITY_LABEL = {1: "[red]HIGH[/red]", 2: "[yellow]MED[/yellow]", 3: "[green]LOW[/green]"}


def main():
    parser = AlertParser(config["suricata"]["eve_log"])
    table = Table(title="NIDS Live Alerts", show_lines=True)
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Sev")
    table.add_column("Source")
    table.add_column("Dest")
    table.add_column("Proto")
    table.add_column("Signature", overflow="fold")

    console.print("[bold green]Starting NIDS live monitor... Ctrl+C to stop.[/bold green]")

    for alert in parser.tail():
        sev = SEVERITY_LABEL.get(alert["severity"], str(alert["severity"]))
        table.add_row(
            alert["timestamp"][:19],
            sev,
            f"{alert['src_ip']}:{alert.get('src_port', '')}",
            f"{alert['dest_ip']}:{alert.get('dest_port', '')}",
            alert.get("proto", ""),
            alert.get("signature", ""),
        )
        console.clear()
        console.print(table)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Stopped.[/bold red]")
