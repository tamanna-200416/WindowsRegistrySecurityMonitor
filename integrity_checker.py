import json
import os


BASELINE_FILE = "data/baseline.json"


def check_integrity(current_entries):

    if not os.path.exists(BASELINE_FILE):
        print("Baseline not found.")
        return 0

    with open(BASELINE_FILE, "r") as file:
        baseline_data = json.load(file)

    baseline_entries = baseline_data["entries"]

    baseline = {
        (entry["root"], entry["registry_path"], entry["name"]): entry["path"]
        for entry in baseline_entries
    }

    current = {
        (entry["root"], entry["registry_path"], entry["name"]): entry["path"]
        for entry in current_entries
    }

    added = []
    deleted = []
    modified = []

    for key in current:

        if key not in baseline:
            added.append(key)

        elif current[key] != baseline[key]:
            modified.append(key)

    for key in baseline:

        if key not in current:
            deleted.append(key)

    print("\n==============================================")
    print("           REGISTRY INTEGRITY CHECK")
    print("==============================================")

    print(f"\nAdded Entries    : {len(added)}")
    print(f"Modified Entries : {len(modified)}")
    print(f"Deleted Entries  : {len(deleted)}")

    if added:
        print("\n[+] ADDED")

        for root, registry_path, name in added:
            print(f"{root} -> {registry_path} -> {name}")

    if modified:
        print("\n[*] MODIFIED")

        for root, registry_path, name in modified:
            print(f"{root} -> {registry_path} -> {name}")

    if deleted:
        print("\n[-] DELETED")

        for root, registry_path, name in deleted:
            print(f"{root} -> {registry_path} -> {name}")

    if not added and not modified and not deleted:
        print("\nSTATUS: Registry is unchanged.")

    total_changes = len(added) + len(modified) + len(deleted)

    return total_changes