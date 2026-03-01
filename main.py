#!/usr/bin/env python3

from src.connect_to_ad import connect_to_ad
from src.search_directory import search_directory

import subprocess
import sys
from datetime import datetime
import json
import csv
import os
import getpass
import logging


# ---------- Logging setup ----------
def setup_logger(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger(__name__)


# ---------- JSON / CSV helpers ----------
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def save_to_csv(list_of_dicts, filename):
    if not list_of_dicts:
        open(filename, "w", encoding="utf-8").close()
        return

    keys = set()
    for r in list_of_dicts:
        if isinstance(r, dict):
            keys.update(r.keys())
    keys = sorted(keys)

    with open(filename, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for r in list_of_dicts:
            if isinstance(r, dict):
                writer.writerow({k: r.get(k, "") for k in keys})


# ---------- Kerbrute ----------
def find_kerbrute(provided_path=None):
    if provided_path:
        if os.path.isfile(provided_path) and os.access(provided_path, os.X_OK):
            return provided_path
        else:
            print(f"[!] Invalid kerbrute path: {provided_path}. Falling back to auto-detect.")

    repo_root = os.path.dirname(os.path.abspath(__file__))
    cand_unix = os.path.join(repo_root, "src", "kerbrute", "kerbrute")
    cand_win  = os.path.join(repo_root, "src", "kerbrute", "kerbrute.exe")

    for cand in (cand_unix, cand_win):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand

    return "kerbrute"


def run_kerbrute(kerbrute_path, kerbrute_cmd, domain=None, userlist=None,
                 spray_password=None, threads=10, safe=False):

    kb  = find_kerbrute(kerbrute_path)
    cmd = [kb]

    if kerbrute_cmd:
        cmd.append(kerbrute_cmd)

    if domain:
        cmd += ["-d", domain]

    if userlist:
        cmd += ["--userfile", userlist]

    if spray_password and kerbrute_cmd == "passwordspray":
        cmd += ["--password", spray_password]

    cmd += ["-t", str(threads)]

    if safe:
        cmd += ["--safe"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError(f"kerbrute binary not found: {kb}")

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    parsed = []

    for line in output.splitlines():
        ln = line.strip()
        if not ln:
            continue

        if "VALID USERNAME" in ln:
            username = ln.split()[-1]
            parsed.append({"source": "kerbrute", "type": "valid_user", "value": username, "raw": ln})

        if "SUCCESS" in ln or "Authenticated" in ln:
            parsed.append({"source": "kerbrute", "type": "success", "raw": ln})

    return parsed, output


# ---------- NTLM Scanner ----------
def run_ntlm_scanner(script_path, target, target_file=None, hashes=None):
    cmd = [sys.executable, script_path, target]

    if target_file:
        cmd += ["-target-file", target_file]

    if hashes:
        cmd += ["-hashes", hashes]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", str(e)


# ---------- Main ----------
def main():

    run_log = f"main_scan_{datetime.now():%Y%m%d_%H%M%S}.log"
    logger = setup_logger(run_log)

    logger.info("Session started.")
    print(f"Run log: {run_log}\n")

    print("Active Directory Enumerator\n")

    server_address = input("LDAP server (e.g., ldap://domain.com): ").strip()
    username       = input(r"Username (e.g., DOMAIN\User): ").strip()
    ldap_password  = getpass.getpass("Password: ")

    try:
        print("\nConnecting...")
        conn = connect_to_ad(server_address, username, ldap_password)
        print("Connection successful.\n")
        logger.info("Connected to %s as %s", server_address, username)
    except Exception as e:
        logger.error("Connection failed: %s", e)
        print(f"Connection failed: {e}")
        return

    search_base = input("Search base (e.g., DC=domain,DC=com): ").strip()

    try:
        print("\nEnumerating users...")
        users = search_directory(conn, search_base, "(objectClass=user)", ["cn", "mail", "memberOf"])

        print("Enumerating groups...")
        groups = search_directory(conn, search_base, "(objectClass=group)", ["cn", "member"])

        print("Enumerating computers...")
        computers = search_directory(conn, search_base, "(objectClass=computer)", ["cn"])

        print("Enumeration complete.\n")

    except Exception as e:
        logger.error("Enumeration error: %s", e)
        print(f"Enumeration error: {e}")
        return

    results = {
        "users": users,
        "groups": groups,
        "computers": computers,
    }

    print("Output format:")
    print("1. JSON")
    print("2. CSV")

    choice = input("Choice: ").strip()

    if choice == "1":
        filename = input("JSON filename: ").strip() or "output.json"
        save_to_json(results, filename)
        print(f"Saved to {filename}")
    elif choice == "2":
        prefix = input("CSV prefix: ").strip() or "output"
        save_to_csv(users, f"{prefix}_users.csv")
        save_to_csv(groups, f"{prefix}_groups.csv")
        save_to_csv(computers, f"{prefix}_computers.csv")
        print("CSV files saved.")
    else:
        print("No output saved.")

    logger.info("Session finished.")
    print("\nDone.")


if __name__ == "__main__":
    main()
