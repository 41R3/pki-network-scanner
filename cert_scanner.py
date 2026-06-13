#!/usr/bin/env python3
"""
SSL/TLS certificate scanner for network-wide PKI visibility.
Discovers, inspects and monitors x509 certificates across hosts/subnets.
"""

import ssl
import socket
import json
import csv
import sys
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
import argparse

# Puertos comunes con certs TLS — no solo 443
COMMON_TLS_PORTS = [443, 8443, 636, 993, 995, 465, 8080, 9443]


def get_cert_der(host: str, port: int, timeout: int = 5) -> bytes | None:
    """Obtiene el certificado raw en formato DER."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Para discovery no rechazamos self-signed
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def parse_cert(host: str, port: int, der_bytes: bytes) -> dict:
    """Parsea el DER a campos útiles usando cryptography (no regex)."""
    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    now = datetime.now(timezone.utc)

    # Subject
    def get_name_attr(name, oid):
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except IndexError:
            return None

    subject_cn = get_name_attr(cert.subject, NameOID.COMMON_NAME)
    issuer_cn  = get_name_attr(cert.issuer,  NameOID.COMMON_NAME)
    issuer_org = get_name_attr(cert.issuer,  NameOID.ORGANIZATION_NAME)

    # SANs — esto es lo que realmente identifica al cert en producción
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName) + \
               [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    # Días hasta expiración
    not_after  = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_left  = (not_after - now).days

    # Self-signed: subject == issuer
    is_self_signed = cert.subject == cert.issuer

    # Fingerprint SHA256 — identifica el cert de forma única
    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":").upper()

    # Key usage
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        key_usage = [attr for attr in [
            "digital_signature"  if ku.digital_signature  else None,
            "key_encipherment"   if ku.key_encipherment   else None,
            "key_cert_sign"      if ku.key_cert_sign       else None,
            "crl_sign"           if ku.crl_sign            else None,
        ] if attr]
    except x509.ExtensionNotFound:
        key_usage = []

    return {
        "host": host,
        "port": port,
        "subject_cn": subject_cn,
        "sans": sans,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "serial_number": hex(cert.serial_number),
        "fingerprint_sha256": fingerprint,
        "is_self_signed": is_self_signed,
        "key_usage": key_usage,
        "status": _expiry_status(days_left),
    }


def _expiry_status(days: int) -> str:
    if days < 0:    return "EXPIRED"
    if days < 14:   return "CRITICAL"   # < 2 semanas
    if days < 30:   return "WARNING"    # < 1 mes
    return "OK"


def scan_host(host: str, port: int) -> dict | None:
    """Intenta conectar y parsear cert. Retorna None si no hay TLS."""
    der = get_cert_der(host, port)
    if der is None:
        return None
    return parse_cert(host, port, der)


def scan_targets(targets: list[tuple[str, int]], workers: int = 50) -> list[dict]:
    """
    Escaneo concurrente — ThreadPoolExecutor para no tardar 10min en una /24.
    """
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, host, port): (host, port)
                   for host, port in targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda r: r["days_until_expiry"])


def expand_targets(hosts: list[str], ports: list[int]) -> list[tuple[str, int]]:
    """Expande CIDRs a IPs individuales — para escanear subnets."""
    targets = []
    for h in hosts:
        try:
            network = ipaddress.ip_network(h, strict=False)
            for ip in network.hosts():
                for p in ports:
                    targets.append((str(ip), p))
        except ValueError:
            for p in ports:
                targets.append((h, p))
    return targets


def export_csv(results: list[dict], path: str):
    if not results:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["sans"] = "; ".join(r["sans"])
            row["key_usage"] = "; ".join(r["key_usage"])
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="cert-discovery: PKI certificate scanner for network visibility"
    )
    parser.add_argument("hosts", nargs="+",
                        help="Hosts, IPs or CIDRs (e.g. 192.168.1.0/24 google.com)")
    parser.add_argument("--ports", nargs="+", type=int, default=[443],
                        help="TLS ports to scan (default: 443)")
    parser.add_argument("--all-ports", action="store_true",
                        help=f"Scan common TLS ports: {COMMON_TLS_PORTS}")
    parser.add_argument("--workers", type=int, default=50,
                        help="Concurrent threads (default: 50)")
    parser.add_argument("--csv", metavar="FILE",
                        help="Export results to CSV")
    parser.add_argument("--expired-only", action="store_true",
                        help="Show only expired/critical certs")
    args = parser.parse_args()

    ports = COMMON_TLS_PORTS if args.all_ports else args.ports
    targets = expand_targets(args.hosts, ports)

    print(f"[*] Scanning {len(targets)} targets with {args.workers} workers...",
          file=sys.stderr)

    results = scan_targets(targets, workers=args.workers)

    if args.expired_only:
        results = [r for r in results if r["status"] in ("EXPIRED", "CRITICAL")]

    # Output JSON a stdout
    print(json.dumps(results, indent=2))

    if args.csv:
        export_csv(results, args.csv)
        print(f"[+] CSV saved to {args.csv}", file=sys.stderr)

    # Resumen en stderr para no ensuciar el JSON
    expired  = sum(1 for r in results if r["status"] == "EXPIRED")
    critical = sum(1 for r in results if r["status"] == "CRITICAL")
    print(f"\n[+] Found {len(results)} certs | EXPIRED: {expired} | CRITICAL (<14d): {critical}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
