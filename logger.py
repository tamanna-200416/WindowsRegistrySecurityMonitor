from datetime import datetime
import os

LOG_FILE = "logs/security_alerts.log"


def log_alert(message):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save alert to log file only
    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

    print(f"Logged: {message}")