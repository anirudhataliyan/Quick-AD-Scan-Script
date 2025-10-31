#!/usr/bin/env python3

from src import connect_to_ad, search_directory  # adjust if your package layout differs
import subprocess
import sys
from datetime import datetime
import json
import csv
import os
import getpass
import platform

# ---------- Simple helpers to persist results ----------
def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

def save_to_csv(list_of_dicts, filename):
    if not list_of_dicts:
        # write header-only file
        open(filename, "w", encoding="utf-8").close()
        return
    # unify keys from all dicts
    keys = set()
    for r in list_of_dicts:
        if isinstance(r, dict):
            keys.update(r.keys())
    keys = sorted(keys)
    with open(filename, "w", newline='', encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        for r in list_of_dicts:
            writer.writerow({k: r.get(k, "") for k in keys})

# ---------- kerbrute discovery & runner ----------
def find_kerbrute(provided_path=None):
    # 1) explicit path
    if provided_path:
        if os.path.isfile(provided_path) and os.access(provided_path, os.X_OK):
            return provided_path

    # 2) repo-relative default: src/kerbrute/kerbrute (unix) or .exe (windows)
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cand_unix = os.path.join(repo_root, "src", "kerbrute", "kerbrute")
    cand_win = os.path.join(repo_root, "src", "kerbrute", "kerbrute.exe")
    for cand in (cand_unix, cand_win):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand

    # 3) fallback to just "kerbrute" (system PATH) — subprocess will raise FileNotFoundError if missing
    return provided_path or "kerbrute"


def run_kerbrute(kerbrute_path, kerbrute_cmd, domain=None, userlist=None, password=None, threads=10, safe=False):
    """
    kerbrute_cmd: e.g. 'userenum', 'passwordspray', 'bruteforce', or other supported
    userlist: path to file with usernames
    password: single password (if command supports)
    Returns list of parsed results (dictionaries) and raw output string.
    """
    kb = find_kerbrute(kerbrute_path)
    cmd = [kb]

    # append the command name if kerbrute expects it as subcommand
    if kerbrute_cmd:
        cmd.append(kerbrute_cmd)

    if domain:
        cmd += ["-d", domain]
    if userlist:
        cmd += [userlist]
    if password and kerbrute_cmd in ("passwordspray", "bruteforce", "bruteuser"):
        # kerbrute CLI flags differ between versions; adjust as needed
        if kerbrute_cmd == "passwordspray":
            cmd += ["--password", password]

    cmd += ["-t", str(threads)]
    if safe:
        cmd += ["--safe"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise RuntimeError(f"kerbrute binary not found at: {kb} (tried repo-relative and PATH)")

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    parsed = []
    # basic parsing heuristic — expand with regexes for your kerbrute version
    for line in output.splitlines():
        l = line.strip()
        if not l:
            continue
        # example patterns (adjust per your kerbrute version)
        if "VALID USERNAME" in l or ("VALID" in l and "USERNAME" in l):
            parts = l.split()
            username = parts[-1]
            parsed.append({"source": "kerbrute", "type": "valid_user", "value": username, "raw": l})
        # success password lines might include words like "SUCCESS" or "Authenticated"
        if "SUCCESS" in l or "Authenticated" in l:
            parsed.append({"source": "kerbrute", "type": "success", "raw": l})

    return parsed, output

# ---------- NTLM scanner runner ----------
def run_ntlm_scanner(script_path, target, target_file=None, hashes=None):
    # script_path should be the path to your ntlm-scanner script (relative or absolute)
    cmd = ["python", script_path, target]
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
    # Create a run-log file instead of hijacking sys.stdout globally
    run_log = f"main_scan_{datetime.now():%Y%m%d_%H%M%S}.log"
    print(f"Run log: {run_log}")

    print("Welcome to Active Directory Enumerator\n")
    server_address = input("Enter the Active Directory server address (e.g., ldap://domain.com): ").strip()
    username = input(r"Enter the username (e.g., DOMAIN\\User): ").strip()
    password = getpass.getpass("Enter the password: ")

    try:
        print("\nConnecting to the Active Directory...")
        conn = connect_to_ad(server_address, username, password)  # adapt to your API
        print("Connection successful!\n")
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    search_base = input("Enter the search base (e.g., DC=domain,DC=com): ").strip()
    print("\nEnumerating objects in the directory...")
    try:
        print("Fetching user accounts...")
        users = search_directory(conn, search_base, '(objectClass=user)', ['cn', 'mail', 'memberOf'])
        # depends on your search_directory return type; normalize to dicts for saving
        user_data = [getattr(entry, "entry_to_json", lambda: entry)() if hasattr(entry, "entry_to_json") else entry for entry in users]

        print("Fetching groups...")
        groups = search_directory(conn, search_base, '(objectClass=group)', ['cn', 'member'])
        group_data = [getattr(entry, "entry_to_json", lambda: entry)() if hasattr(entry, "entry_to_json") else entry for entry in groups]

        print("Fetching computers...")
        computers = search_directory(conn, search_base, '(objectClass=computer)', ['cn'])
        computer_data = [getattr(entry, "entry_to_json", lambda: entry)() if hasattr(entry, "entry_to_json") else entry for entry in computers]

        print("\nEnumeration completed successfully.")
    except Exception as e:
        print(f"Enumeration error: {e}")
        return

    results = {
        "users": user_data,
        "groups": group_data,
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
    elif output_choice == "2":
        filename_prefix = input("Enter the CSV filename prefix (e.g., output): ").strip() or "output"
        save_to_csv(user_data, f"{filename_prefix}_users.csv")
        save_to_csv(group_data, f"{filename_prefix}_groups.csv")
        save_to_csv(computer_data, f"{filename_prefix}_computers.csv")
        print(f"Results saved as {filename_prefix}_users.csv, {filename_prefix}_groups.csv, and {filename_prefix}_computers.csv.")
    else:
        print("Invalid choice. No output saved.")

    # Optionally run NTLM scanner
    run_ntlm = input("\nDo you want to run the NTLM Scanner? (yes/no): ").strip().lower()
    if run_ntlm == "yes":
        script_path = input("Enter the path to ntlm-scanner.py (or press Enter if it's in current dir): ").strip() or "ntlm-scanner.py"
        target = input("Enter the target (e.g., an IP address or domain): ").strip()
        target_file = input("Enter the target file path (or press Enter to skip): ").strip() or None
        hashes = input("Enter the hashes (LMHASH:NTHASH format) or press Enter to skip: ").strip() or None
        rc, out, err = run_ntlm_scanner(script_path, target, target_file, hashes)
        with open("ntlm_scanner_output.txt", "w", encoding="utf-8") as fh:
            fh.write(out or "")
            if err:
                fh.write("\n--- STDERR ---\n")
                fh.write(err)
        print(f"NTLM Scanner results saved to ntlm_scanner_output.txt (rc={rc}).")

    # Optionally run kerbrute
    kerbrute_op = input("\nDo you want to run Kerbrute pre-auth bruteforcing? (y/N): ").strip().lower()
    if kerbrute_op == "y":
        provided_path = input("Provide kerbrute path or press Enter to auto-detect (src/kerbrute/kerbrute): ").strip() or None
        kerbrute_cmd = input("Kerbrute command (e.g., userenum, passwordspray): ").strip() or "userenum"
        domain = input("Target domain (e.g., example.com): ").strip() or None
        userlist = input("Path to usernames file (or press Enter to create one from LDAP users): ").strip() or None
        if not userlist:
            # write usernames to temporary file from user_data
            tmp_userfile = "kerbrute_users.txt"
            with open(tmp_userfile, "w", encoding="utf-8") as fh:
                for u in user_data:
                    # try to extract a sensible username; adjust per your user_data structure
                    if isinstance(u, dict):
                        v = u.get("sAMAccountName") or u.get("cn") or u.get("mail")
                        if v:
                            fh.write(str(v) + "\n")
                    else:
                        fh.write(str(u) + "\n")
            userlist = tmp_userfile
            print(f"Wrote {len(user_data)} users to {tmp_userfile}")

        password = None
        if kerbrute_cmd == "passwordspray":
            password = getpass.getpass("Password to spray: ")

        threads = input("Threads (default 10): ").strip()
        threads = int(threads) if threads.isdigit() else 10
        safe_flag = input("Use safe mode? (avoid account lockouts) (y/N): ").strip().lower() == "y"

        try:
            parsed, raw = run_kerbrute(provided_path, kerbrute_cmd, domain=domain, userlist=userlist, password=password, threads=threads, safe=safe_flag)
            # save parsed + raw
            save_to_json(parsed, "kerbrute_parsed.json")
            with open("kerbrute_raw.txt", "w", encoding="utf-8") as fh:
                fh.write(raw or "")
            print(f"Kerbrute parsed results saved to kerbrute_parsed.json; raw output to kerbrute_raw.txt")
        except Exception as e:
            print(f"Kerbrute failed: {e}")

    print("\nFinished. See log file if needed:", run_log)


if __name__ == "__main__":
    main()
