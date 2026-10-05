SUSPICIOUS_LOCATIONS = [
    r"\AppData\Local\Temp",
    r"\AppData\Roaming",
    r"\Temp",
    r"\Startup"
]

SUSPICIOUS_EXTENSIONS = [
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".ps1"
]


def analyze_entry(entry):

    path = entry["path"].lower()

    reasons = []

    for location in SUSPICIOUS_LOCATIONS:
        if location.lower() in path:
            reasons.append(
                "Runs from a suspicious or temporary location"
            )

    for extension in SUSPICIOUS_EXTENSIONS:
        if path.endswith(extension):
            reasons.append(
                f"Contains script file type: {extension}"
            )

    return reasons