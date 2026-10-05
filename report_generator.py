import os
from datetime import datetime
from detector import analyze_entry

REPORT_FILE = "reports/registry_report.txt"


def generate_report(entries):

    os.makedirs("reports", exist_ok=True)

    suspicious_entries = []

    for entry in entries:
        reasons = list(dict.fromkeys(analyze_entry(entry)))

        if reasons:
            suspicious_entries.append({
                "entry": entry,
                "reasons": reasons
            })

    normal_count = len(entries) - len(suspicious_entries)

    with open(REPORT_FILE, "w") as file:

        file.write("==============================================\n")
        file.write("       WINDOWS REGISTRY SECURITY REPORT\n")
        file.write("==============================================\n\n")

        file.write(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        file.write(f"Total Registry Entries : {len(entries)}\n")
        file.write(f"Normal Entries         : {normal_count}\n")
        file.write(f"Suspicious Entries     : {len(suspicious_entries)}\n\n")

        if suspicious_entries:
            file.write("SECURITY STATUS: REVIEW RECOMMENDED\n")
        else:
            file.write("SECURITY STATUS: NO SUSPICIOUS PATTERN DETECTED\n")

        file.write("\n----------------------------------------------\n")
        file.write("Registry Entries\n")
        file.write("----------------------------------------------\n\n")

        for entry in entries:

            file.write(f"Root          : {entry['root']}\n")
            file.write(f"Registry Path : {entry['registry_path']}\n")
            file.write(f"Name          : {entry['name']}\n")
            file.write(f"Value         : {entry['path']}\n")

            reasons = list(dict.fromkeys(analyze_entry(entry)))

            if reasons:
                file.write("Status        : REVIEW RECOMMENDED\n")

                for reason in reasons:
                    file.write(f"Reason        : {reason}\n")
            else:
                file.write("Status        : No suspicious pattern detected\n")

            file.write("\n")

    print("\nSecurity report generated successfully!")
    print(f"Saved to: {REPORT_FILE}")