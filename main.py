#!/usr/bin/env python3

from src import connect_to_ad, search_directory
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


# ---------- Simple helpers to persist results ----------
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def save_to_csv(list_of_dicts, filename):
    if not list_of_dicts:
        open(filename, "w", encoding="utf-8").close()
        return
    # Unify keys from all dicts
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


# ---------- kerbrute discovery & runner ----------
def find_kerbrute(provided_path=None):
    # 1) Explicit path — error loudly if provided but invalid
    if provided_path:
        if os.path.isfile(provided_path) and os.access(provided_path, os.X_OK):
            return provided_path
        else:
            # FIX: was silently falling through; now warns the user clearly
            print(f"[!] Warning: provided kerbrute path '{provided_path}' is invalid or not executable. Falling back to auto-detect...")

    # 2) Repo-relative default: src/kerbrute/kerbrute (unix) or .exe (windows)
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cand_unix = os.path.join(repo_root, "src", "kerbrute", "kerbrute")
    cand_win  = os.path.join(repo_root, "src", "kerbrute", "kerbrute.exe")
    for cand in (cand_unix, cand_win):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand

    # 3) Fallback to system PATH
    return "kerbrute"


def run_kerbrute(kerbrute_path, kerbrute_cmd, domain=None, userlist=None,
                 spray_password=None, threads=10, safe=False):
    """
    kerbrute_cmd : e.g. 'userenum', 'passwordspray', 'bruteforce'
    userlist     : path to file with usernames
    spray_password: single password used for passwordspray (renamed to avoid
                    shadowing the LDAP password in main())
    Returns (list[dict], raw_output_str)
    """
    kb  = find_kerbrute(kerbrute_path)
    cmd = [kb]

    if kerbrute_cmd:
        cmd.append(kerbrute_cmd)

    if domain:
        cmd += ["-d", domain]

    # FIX: kerbrute expects --userfile / -U flag, not a bare positional arg
    if userlist:
        cmd += ["--userfile", userlist]

    if spray_password and kerbrute_cmd in ("passwordspray", "bruteforce", "bruteuser"):
        if kerbrute_cmd == "passwordspray":
            cmd += ["--password", spray_password]

    cmd += ["-t", str(threads)]
    if safe:
        cmd += ["--safe"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError(
            f"kerbrute binary not found at: {kb} (tried repo-relative path and system PATH)"
        )

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    parsed = []
    for line in output.splitlines():
        ln = line.strip()
        if not ln:
            continue
        if "VALID USERNAME" in ln or ("VALID" in ln and "USERNAME" in ln):
            parts    = ln.split()
            username = parts[-1]
            parsed.append({"source": "kerbrute", "type": "valid_user", "value": username, "raw": ln})
        if "SUCCESS" in ln or "Authenticated" in ln:
            parsed.append({"source": "kerbrute", "type": "success", "raw": ln})

    return parsed, output


# ---------- NTLM scanner runner ----------
def run_ntlm_scanner(script_path, target, target_file=None, hashes=None):
    # FIX: use sys.executable so the correct Python (3) is always invoked
    cmd = [sys.executable, script_path, target]
    if target_file:
        cmd += ["-target-file", target_file]
    if hashes:
        cmd += ["-hashes", hashes]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as e:
        return 1, "", f"Failed to run ntlm scanner: {e}"


# ---------- main flow ----------
def main():
    run_log = f"main_scan_{datetime.now():%Y%m%d_%H%M%S}.log"
    # FIX: logger now actually writes to the log file (was declared but never used before)
    logger = setup_logger(run_log)
    logger.info("Session started.")
    print(f"Run log: {run_log}\n")

    print("Welcome to Active Directory Enumerator\n")
    server_address = input("Enter the Active Directory server address (e.g., ldap://domain.com): ").strip()
    username       = input(r"Enter the username (e.g., DOMAIN\\User): ").strip()
    ldap_password  = getpass.getpass("Enter the password: ")   # FIX: renamed from 'password' to avoid later shadowing

    try:
        print("\nConnecting to the Active Directory...")
        conn = connect_to_ad(server_address, username, ldap_password)
        logger.info("Connected to %s as %s", server_address, username)
        print("Connection successful!\n")
    except Exception as e:
        logger.error("Failed to connect: %s", e)
        print(f"Failed to connect: {e}")
        return

    search_base = input("Enter the search base (e.g., DC=domain,DC=com): ").strip()
    print("\nEnumerating objects in the directory...")

    try:
        print("Fetching user accounts...")
        users = search_directory(conn, search_base, "(objectClass=user)", ["cn", "mail", "memberOf"])
        # FIX: use default argument (e=entry) to correctly capture loop variable in lambda
        user_data = [
            getattr(entry, "entry_to_json", lambda e=entry: e)()
            if hasattr(entry, "entry_to_json") else entry
            for entry in users
        ]

        print("Fetching groups...")
        groups = search_directory(conn, search_base, "(objectClass=group)", ["cn", "member"])
        group_data = [
            getattr(entry, "entry_to_json", lambda e=entry: e)()
            if hasattr(entry, "entry_to_json") else entry
            for entry in groups
        ]

        print("Fetching computers...")
        computers = search_directory(conn, search_base, "(objectClass=computer)", ["cn"])
        computer_data = [
            getattr(entry, "entry_to_json", lambda e=entry: e)()
            if hasattr(entry, "entry_to_json") else entry
            for entry in computers
        ]

        logger.info("Enumeration complete — users: %d, groups: %d, computers: %d",
                    len(user_data), len(group_data), len(computer_data))
        print("\nEnumeration completed successfully.")
    except Exception as e:
        logger.error("Enumeration error: %s", e)
        print(f"Enumeration error: {e}")
        return

    results = {
        "users":     user_data,
        "groups":    group_data,
        "computers": computer_data,
    }

    # Output selection
    print("\nChoose an output format:")
    print("1. JSON")
    print("2. CSV")
    output_choice = input("Enter your choice (1 or 2): ").strip()

    if output_choice == "1":
        filename = input("Enter the JSON filename (e.g., output.json): ").strip() or "output.json"
        save_to_json(results, filename)
        print(f"Results saved to {filename}.")
        logger.info("Saved JSON results to %s", filename)
    elif output_choice == "2":
        prefix = input("Enter the CSV filename prefix (e.g., output): ").strip() or "output"
        save_to_csv(user_data,     f"{prefix}_users.csv")
        save_to_csv(group_data,    f"{prefix}_groups.csv")
        save_to_csv(computer_data, f"{prefix}_computers.csv")
        print(f"Results saved as {prefix}_users.csv, {prefix}_groups.csv, {prefix}_computers.csv.")
        logger.info("Saved CSV results with prefix '%s'", prefix)
    else:
        print("Invalid choice. No output saved.")

    # Optionally run NTLM scanner
    run_ntlm = input("\nDo you want to run the NTLM Scanner? (yes/no): ").strip().lower()
    if run_ntlm == "yes":
        script_path = input("Path to ntlm-scanner.py (Enter for current dir): ").strip() or "ntlm-scanner.py"
        target      = input("Target (IP or domain): ").strip()
        target_file = input("Target file path (Enter to skip): ").strip() or None
        hashes      = input("Hashes (LMHASH:NTHASH) or Enter to skip: ").strip() or None
        rc, out, err = run_ntlm_scanner(script_path, target, target_file, hashes)
        with open("ntlm_scanner_output.txt", "w", encoding="utf-8") as fh:
            fh.write(out or "")
            if err:
                fh.write("\n--- STDERR ---\n")
                fh.write(err)
        print(f"NTLM Scanner results saved to ntlm_scanner_output.txt (rc={rc}).")
        logger.info("NTLM scanner finished with return code %d", rc)

    # Optionally run kerbrute
    kerbrute_op = input("\nDo you want to run Kerbrute pre-auth bruteforcing? (y/N): ").strip().lower()
    if kerbrute_op == "y":
        provided_path = input("Kerbrute path or Enter to auto-detect: ").strip() or None
        kerbrute_cmd  = input("Kerbrute command (userenum / passwordspray): ").strip() or "userenum"
        domain        = input("Target domain (e.g., example.com): ").strip() or None
        userlist      = input("Path to usernames file (Enter to generate from LDAP results): ").strip() or None

        if not userlist:
            tmp_userfile = "kerbrute_users.txt"
            with open(tmp_userfile, "w", encoding="utf-8") as fh:
                for u in user_data:
                    if isinstance(u, dict):
                        v = u.get("sAMAccountName") or u.get("cn") or u.get("mail")
                        if v:
                            fh.write(str(v) + "\n")
                    else:
                        fh.write(str(u) + "\n")
            userlist = tmp_userfile
            print(f"Wrote {len(user_data)} users to {tmp_userfile}")

        # FIX: use a separate variable so the LDAP password above is never overwritten
        spray_password = None
        if kerbrute_cmd == "passwordspray":
            spray_password = getpass.getpass("Password to spray: ")

        threads_input = input("Threads (default 10): ").strip()
        threads       = int(threads_input) if threads_input.isdigit() else 10
        safe_flag     = input("Use safe mode? (y/N): ").strip().lower() == "y"

        try:
            parsed, raw = run_kerbrute(
                provided_path, kerbrute_cmd,
                domain=domain, userlist=userlist,
                spray_password=spray_password,
                threads=threads, safe=safe_flag,
            )
            save_to_json(parsed, "kerbrute_parsed.json")
            with open("kerbrute_raw.txt", "w", encoding="utf-8") as fh:
                fh.write(raw or "")
            print("Kerbrute parsed results → kerbrute_parsed.json | raw output → kerbrute_raw.txt")
            logger.info("Kerbrute finished — %d results parsed", len(parsed))
        except Exception as e:
            logger.error("Kerbrute failed: %s", e)
            print(f"Kerbrute failed: {e}")

    logger.info("Session finished.")
    print("\nFinished. See log file:", run_log)


if __name__ == "__main__":
    main()
