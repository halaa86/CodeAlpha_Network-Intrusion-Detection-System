#!/usr/bin/env python3
import ipaddress
import logging
import subprocess
import time
from datetime import datetime, timedelta

from config_loader import load_config
from alert_parser import AlertParser

config = load_config()
logging.basicConfig(
    level=config["logging"]["level"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(config["logging"]["file"]),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("auto_block")

BLOCKED = {}  # ip -> expiry datetime


def is_whitelisted(ip: str, whitelist) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in whitelist:
        if "/" in entry:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        elif ip == entry:
            return True
    return False


def block_ip(ip: str, duration: int):
    if ip in BLOCKED and BLOCKED[ip] > datetime.now():
        return
    log.warning("Blocking %s for %ss", ip, duration)
    subprocess.run(
        ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        check=True,
    )
    BLOCKED[ip] = datetime.now() + timedelta(seconds=duration)


def unblock_expired():
    now = datetime.now()
    for ip, expiry in list(BLOCKED.items()):
        if expiry <= now:
            log.info("Unblocking %s (expired)", ip)
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=False,
            )
            BLOCKED.pop(ip, None)


def main():
    cfg = config["response"]
    if not cfg["enabled"]:
        log.info("Response disabled in config. Exiting.")
        return

    parser = AlertParser(config["suricata"]["eve_log"])
    log.info("Monitoring Suricata alerts...")

    for alert in parser.tail():
        unblock_expired()
        ip = alert.get("src_ip")
        severity = alert.get("severity")
        if not ip:
            continue
        if severity not in cfg["block_severities"]:
            continue
        if is_whitelisted(ip, cfg["whitelist"]):
            log.debug("Skipping whitelisted IP %s", ip)
            continue
        block_ip(ip, cfg["block_duration_seconds"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("Shutting down.")
