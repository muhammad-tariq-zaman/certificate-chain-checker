"""Check a PEM certificate chain: expiry and issuer/subject linkage.

Usage: python3 main.py chain.pem [--today 2026-10-30]
Each certificate is decoded with the standard library ssl module. A chain
link is valid when one certificate's issuer matches the next one's subject.
A single certificate is reported as such (no chain to verify).
"""
import argparse
import ssl
import sys
import tempfile
import os
from datetime import date, datetime


def split_pem(text):
    blocks, current = [], []
    for line in text.splitlines():
        if line.strip() == "-----BEGIN CERTIFICATE-----":
            current = [line]
        elif line.strip() == "-----END CERTIFICATE-----":
            current.append(line)
            blocks.append("\n".join(current))
        elif current:
            current.append(line)
    return blocks


def decode_block(block):
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(block + "\n")
        info = ssl._ssl._test_decode_cert(path)
    finally:
        os.unlink(path)
    subject = tuple(x[0][1] for x in info["subject"])
    issuer = tuple(x[0][1] for x in info["issuer"])
    not_after = datetime.strptime(info["notAfter"], "%b %d %H:%M:%S %Y %Z").date()
    return {"subject": subject, "issuer": issuer, "not_after": not_after}


def check_chain(certs, today):
    problems = []
    for i, cert in enumerate(certs):
        if cert["not_after"] < today:
            problems.append(f"certificate {i + 1}: EXPIRED on {cert['not_after'].isoformat()}")
    for i in range(len(certs) - 1):
        if certs[i]["issuer"] != certs[i + 1]["subject"]:
            problems.append(f"link {i + 1}->{i + 2}: issuer does not match next subject (chain broken)")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="PEM file with one or more certificates")
    parser.add_argument("--today", default=None, help="Reference date YYYY-MM-DD (default: today)")
    args = parser.parse_args(argv)
    today = date.fromisoformat(args.today) if args.today else date.today()
    with open(args.path, encoding="utf-8") as f:
        blocks = split_pem(f.read())
    if not blocks:
        print("ERROR: no certificates found in file")
        return 1
    certs = [decode_block(b) for b in blocks]
    for i, cert in enumerate(certs, 1):
        state = "EXPIRED" if cert["not_after"] < today else "OK"
        print(f"certificate {i}: {state} (expires {cert['not_after'].isoformat()})")
    if len(certs) == 1:
        print("Single certificate: no chain to verify.")
    problems = check_chain(certs, today)
    for problem in problems:
        print(f"- {problem}")
    print(f"Chain verdict: {'BROKEN' if problems else 'OK'} ({len(certs)} certificate(s)).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
