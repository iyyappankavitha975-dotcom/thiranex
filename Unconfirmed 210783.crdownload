"""
Port Scanner Module
Scans for open ports and checks for weak configurations.
"""

import socket
import concurrent.futures
from datetime import datetime

# Common ports and their services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports considered risky if open
RISKY_PORTS = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet is unencrypted — use SSH instead",
    445: "SMB port — common ransomware target",
    3389: "RDP exposed — brute-force risk",
    6379: "Redis often runs without authentication",
    27017: "MongoDB often runs without authentication",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempts to connect to a single port.
    Returns a dict with port info.
    """
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "status": "closed",
        "risk": None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["status"] = "open"
            if port in RISKY_PORTS:
                result["risk"] = RISKY_PORTS[port]
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return result


def scan_ports(host: str, ports: list = None, max_workers: int = 50) -> list:
    """
    Scans multiple ports concurrently.
    Returns list of open port results.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print(f"[*] Scanning {host} — checking {len(ports)} ports...")
    start = datetime.now()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["status"] == "open":
                open_ports.append(result)
                status = f"  [OPEN] Port {result['port']} ({result['service']})"
                if result["risk"]:
                    status += f" ⚠ RISK: {result['risk']}"
                print(status)

    elapsed = (datetime.now() - start).total_seconds()
    print(f"[*] Port scan complete in {elapsed:.2f}s — {len(open_ports)} open port(s) found.\n")
    return sorted(open_ports, key=lambda x: x["port"])
