import winreg
import json
import time

from logger import log_alert
from database import save_event


BASELINE_FILE = "data/baseline.json"

RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
TEST_PATH = r"Software\WindowsRegistrySecurityMonitor\Test"


def scan_registry(root_key, root_name, registry_path):

    entries = []

    try:
        key = winreg.OpenKey(root_key, registry_path)

        index = 0

        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, index)

                entries.append({
                    "root": root_name,
                    "name": name,
                    "path": value,
                    "registry_path": registry_path
                })

                index += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except (FileNotFoundError, PermissionError, OSError):
        pass

    return entries


def get_current_registry():

    user_entries = scan_registry(
        winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER",
        RUN_PATH
    )

    system_entries = scan_registry(
        winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE",
        RUN_PATH
    )

    test_entries = scan_registry(
        winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER",
        TEST_PATH
    )

    return user_entries + system_entries + test_entries


def load_baseline():

    with open(BASELINE_FILE, "r") as file:
        data = json.load(file)

    return data["entries"]


def create_snapshot(entries):

    return {
        (
            entry["root"],
            entry["registry_path"],
            entry["name"]
        ): entry["path"]

        for entry in entries
    }


def monitor():

    baseline_entries = load_baseline()
    baseline = create_snapshot(baseline_entries)

    print("==============================================")
    print("       CONTINUOUS REGISTRY MONITOR")
    print("==============================================")
    print()
    print("Monitoring Windows Registry...")
    print("Check interval: 5 seconds")
    print("Press Ctrl+C to stop.")
    print()

    while True:

        current_entries = get_current_registry()
        current = create_snapshot(current_entries)

        # Detect NEW entries
        for key in current:

            if key not in baseline:

                message = (
                    f"NEW Registry Entry: "
                    f"{key[0]} -> {key[2]} | {current[key]}"
                )

                print(f"[ALERT] {message}")
                log_alert(message)

                save_event(
                    "NEW",
                    key[0],
                    key[1],
                    key[2],
                    current[key]
                )

        # Detect MODIFIED entries
        for key in current:

            if key in baseline and current[key] != baseline[key]:

                message = (
                    f"MODIFIED Registry Entry: "
                    f"{key[0]} -> {key[2]} | {current[key]}"
                )

                print(f"[ALERT] {message}")
                log_alert(message)

                save_event(
                    "MODIFIED",
                    key[0],
                    key[1],
                    key[2],
                    current[key]
                )

        # Detect DELETED entries
        for key in baseline:

            if key not in current:

                message = (
                    f"DELETED Registry Entry: "
                    f"{key[0]} -> {key[2]}"
                )

                print(f"[ALERT] {message}")
                log_alert(message)

                save_event(
                    "DELETED",
                    key[0],
                    key[1],
                    key[2],
                    ""
                )

        baseline = current

        time.sleep(5)


if __name__ == "__main__":

    try:
        monitor()

    except KeyboardInterrupt:

        print("\nMonitoring stopped.")