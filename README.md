Windows Registry Security Monitor
A Python-based cybersecurity project that monitors selected Windows Registry locations, detects suspicious Registry patterns, identifies Registry changes, and generates security alerts and reports.

Features
- Scans Windows Registry startup locations
- Detects suspicious Registry patterns
- Creates a Registry baseline
- Detects Added, Modified and Deleted entries
- Provides continuous Registry monitoring
- Generates security alerts and logs
- Stores events using SQLite
- Generates security reports
- Provides a Tkinter-based GUI dashboard
  
Technologies Used
- Python 3
- Windows Registry (winreg)
- Tkinter
- SQLite
- JSON
- Git & GitHub

Monitored Registry Locations
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
A separate Registry test path is used for safe testing.

Project Structure
main.py – Registry scanning
detector.py – Suspicious pattern detection
baseline_manager.py – Baseline creation
integrity_checker.py – Integrity checking
monitor.py – Continuous monitoring
logger.py – Security alert logging
database.py – SQLite event storage
report_generator.py – Security report generation
gui.py – Graphical dashboard
test_registry.py – Safe Registry testing

How It Works
Registry Scan → Suspicious Pattern Detection → Baseline Comparison → Added/Modified/Deleted Detection → Security Alerts & Logs → Security Report → GUI Dashboard

Testing
The project was tested for Registry scanning, suspicious entry detection, added/modified/deleted entry detection, continuous monitoring, security logging, and report generation.

How to Run
python main.py
python gui.py
python monitor.py

Security Note
This project uses rule-based detection. A suspicious Registry pattern does not automatically mean that an entry is malware; it indicates that the entry requires further review.

Future Improvements
Advanced anomaly detection, digital signature verification, file hash verification, notification-based alerts, and event-driven Registry monitoring.

Purpose
Developed as an educational cybersecurity project to understand Windows Registry security, persistence monitoring, integrity checking, logging, and security reporting.
