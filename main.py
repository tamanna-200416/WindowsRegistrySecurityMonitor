import winreg

from detector import analyze_entry
from baseline_manager import create_baseline
from integrity_checker import check_integrity
from logger import log_alert
from report_generator import generate_report


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
                    "name": name,
                    "path": value,
                    "root": root_name,
                    "registry_path": registry_path
                })

                index += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except (FileNotFoundError, PermissionError, OSError):
        pass

    return entries


def run_scan():

    print("==============================================")
    print("       WINDOWS REGISTRY SECURITY MONITOR")
    print("==============================================")
    print()

    print("AUTORUN REGISTRY SCAN")
    print("----------------------------------------------")

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

    all_entries = user_entries + system_entries + test_entries

    for entry in all_entries:

        print(f"\nRegistry: {entry['root']}")
        print(f"Name: {entry['name']}")
        print(f"Path: {entry['path']}")

        reasons = analyze_entry(entry)

        if reasons:

            print("Status: REVIEW RECOMMENDED")

            for reason in reasons:
                print(f"Reason: {reason}")

            log_alert(
                f"Suspicious Registry Entry: "
                f"{entry['root']} -> {entry['registry_path']} -> "
                f"{entry['name']} | {entry['path']}"
            )

        else:
            print("Status: No suspicious pattern detected")

    print("\n----------------------------------------------")
    print(f"Total Startup Entries: {len(all_entries)}")
    print(f"User Entries: {len(user_entries)}")
    print(f"System Entries: {len(system_entries)}")

    check_integrity(all_entries)
    generate_report(all_entries)


if __name__ == "__main__":
    run_scan()

# Baseline already created, so keep this commented.
# create_baseline(all_entries)