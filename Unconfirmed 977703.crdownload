"""
Configuration Checker Module
Checks for weak or insecure configurations in web services and common protocols.
"""

import socket
import ssl
import re
from datetime import datetime, timezone


def check_http_headers(host: str, port: int = 80, use_ssl: bool = False, timeout: float = 5.0) -> list:
    """
    Sends an HTTP request and checks response headers for security misconfigurations.
    Returns list of findings.
    """
    findings = []
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=timeout)
            conn = context.wrap_socket(raw, server_hostname=host)
        else:
            conn = socket.create_connection((host, port), timeout=timeout)

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n\r\n"
        )
        conn.sendall(request.encode())

        response = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        conn.close()

        headers_raw = response.decode("utf-8", errors="ignore").split("\r\n\r\n")[0]
        headers = {}
        for line in headers_raw.split("\r\n")[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        # Security header checks
        REQUIRED_HEADERS = {
            "strict-transport-security": "Missing HSTS — browsers won't force HTTPS",
            "x-content-type-options": "Missing X-Content-Type-Options — MIME sniffing risk",
            "x-frame-options": "Missing X-Frame-Options — clickjacking risk",
            "content-security-policy": "Missing CSP — XSS risk increased",
            "x-xss-protection": "Missing X-XSS-Protection header",
            "referrer-policy": "Missing Referrer-Policy header",
        }

        for header, issue in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append({
                    "check": "HTTP Security Headers",
                    "issue": issue,
                    "severity": "MEDIUM",
                    "detail": f"Header '{header}' not found in response",
                })

        # Check for server version disclosure
        if "server" in headers:
            server_val = headers["server"]
            if re.search(r"[\d.]{3,}", server_val):
                findings.append({
                    "check": "Server Version Disclosure",
                    "issue": f"Server header reveals version info: {server_val}",
                    "severity": "LOW",
                    "detail": "Attackers can use version info to target known vulnerabilities",
                })

        # Check for cookies without Secure/HttpOnly
        if "set-cookie" in headers:
            cookie = headers["set-cookie"]
            if "secure" not in cookie.lower():
                findings.append({
                    "check": "Cookie Security",
                    "issue": "Cookie missing 'Secure' flag — sent over HTTP",
                    "severity": "MEDIUM",
                    "detail": cookie[:100],
                })
            if "httponly" not in cookie.lower():
                findings.append({
                    "check": "Cookie Security",
                    "issue": "Cookie missing 'HttpOnly' flag — accessible via JavaScript",
                    "severity": "MEDIUM",
                    "detail": cookie[:100],
                })

    except Exception as e:
        findings.append({
            "check": "HTTP Config Check",
            "issue": f"Could not complete HTTP check: {e}",
            "severity": "INFO",
            "detail": "",
        })

    return findings


def check_ssl_config(host: str, port: int = 443, timeout: float = 5.0) -> list:
    """
    Checks SSL/TLS configuration for weak settings.
    Returns list of findings.
    """
    findings = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert(binary_form=False)
                cipher = conn.cipher()
                version = conn.version()

                # TLS version check
                if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    findings.append({
                        "check": "TLS Version",
                        "issue": f"Weak TLS version in use: {version}",
                        "severity": "HIGH",
                        "detail": "Use TLS 1.2 or TLS 1.3 only",
                    })
                else:
                    findings.append({
                        "check": "TLS Version",
                        "issue": f"TLS version: {version} (acceptable)",
                        "severity": "INFO",
                        "detail": "",
                    })

                # Cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    if any(w in cipher_name.upper() for w in ["RC4", "DES", "MD5", "NULL", "EXPORT", "ANON"]):
                        findings.append({
                            "check": "Cipher Suite",
                            "issue": f"Weak cipher in use: {cipher_name}",
                            "severity": "HIGH",
                            "detail": "RC4, DES, MD5, NULL, EXPORT, ANON ciphers are insecure",
                        })

                # Certificate expiry
                if cert and "notAfter" in cert:
                    expiry_str = cert["notAfter"]
                    expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        findings.append({
                            "check": "SSL Certificate",
                            "issue": f"Certificate EXPIRED {abs(days_left)} days ago",
                            "severity": "CRITICAL",
                            "detail": f"Expired on {expiry_str}",
                        })
                    elif days_left < 30:
                        findings.append({
                            "check": "SSL Certificate",
                            "issue": f"Certificate expires in {days_left} days",
                            "severity": "HIGH",
                            "detail": f"Expires: {expiry_str}",
                        })
                    else:
                        findings.append({
                            "check": "SSL Certificate",
                            "issue": f"Certificate valid for {days_left} more days",
                            "severity": "INFO",
                            "detail": f"Expires: {expiry_str}",
                        })

    except ssl.SSLError as e:
        findings.append({
            "check": "SSL Config",
            "issue": f"SSL error: {e}",
            "severity": "HIGH",
            "detail": "SSL handshake failed — may indicate misconfiguration",
        })
    except Exception as e:
        findings.append({
            "check": "SSL Config",
            "issue": f"Could not check SSL: {e}",
            "severity": "INFO",
            "detail": "",
        })

    return findings


def run_config_checks(host: str, open_ports: list) -> list:
    """
    Runs all configuration checks relevant to open ports.
    Returns combined list of findings.
    """
    print(f"[*] Checking configurations on {host}...")
    all_findings = []
    open_port_nums = [p["port"] for p in open_ports]

    if 80 in open_port_nums:
        print("  [HTTP] Checking HTTP headers on port 80...")
        findings = check_http_headers(host, 80)
        all_findings.extend(findings)

    if 443 in open_port_nums:
        print("  [HTTPS] Checking SSL/TLS config on port 443...")
        ssl_findings = check_ssl_config(host, 443)
        all_findings.extend(ssl_findings)
        https_findings = check_http_headers(host, 443, use_ssl=True)
        all_findings.extend(https_findings)

    if 8080 in open_port_nums:
        print("  [HTTP-Alt] Checking HTTP headers on port 8080...")
        findings = check_http_headers(host, 8080)
        all_findings.extend(findings)

    high = len([f for f in all_findings if f["severity"] in ("HIGH", "CRITICAL")])
    medium = len([f for f in all_findings if f["severity"] == "MEDIUM"])
    print(f"[*] Config check complete — {high} high/critical, {medium} medium issue(s) found.\n")
    return all_findings
