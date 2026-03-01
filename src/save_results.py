import json
import csv


def save_to_json(data, filename):
    with open(filename, "w", encoding="utf-8") as file:   # FIX: added encoding
        json.dump(data, file, indent=4, ensure_ascii=False)


def save_to_csv(data, filename):
    # FIX: guard against empty list before accessing data[0] (was an IndexError/KeyError)
    if not data:
        open(filename, "w", encoding="utf-8").close()
        return

    # Unify keys from all rows so missing keys in some rows don't crash the writer
    keys = set()
    for row in data:
        if isinstance(row, dict):
            keys.update(row.keys())
    keys = sorted(keys)

    with open(filename, "w", newline="", encoding="utf-8") as file:   # FIX: added encoding
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for row in data:
            if isinstance(row, dict):
                writer.writerow({k: row.get(k, "") for k in keys})
