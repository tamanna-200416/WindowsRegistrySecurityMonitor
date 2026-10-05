import json
import os
from datetime import datetime


BASELINE_FILE = "data/baseline.json"


def create_baseline(entries):
    os.makedirs("data", exist_ok=True)

    baseline = {
        "created_at": datetime.now().isoformat(),
        "entries": entries
    }

    with open(BASELINE_FILE, "w") as file:
        json.dump(baseline, file, indent=4)

    print("\nBaseline created successfully!")
    print(f"Saved to: {BASELINE_FILE}")