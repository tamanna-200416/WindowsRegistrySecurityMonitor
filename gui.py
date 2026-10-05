import tkinter as tk
from tkinter import messagebox
import os
import subprocess
import winreg

from main import scan_registry
from integrity_checker import check_integrity
from report_generator import generate_report
from detector import analyze_entry
from database import get_events, create_database


# ============================================================
# GLOBALS
# ============================================================

monitor_process = None


# ============================================================
# COLORS
# ============================================================

BG = "#0b1120"
SIDEBAR = "#111827"
CARD = "#172033"
CARD2 = "#1d293d"

TEXT = "#f8fafc"
MUTED = "#8b9bb4"

BLUE = "#38bdf8"
GREEN = "#22c55e"
RED = "#ef4444"
YELLOW = "#f59e0b"


# ============================================================
# ACTIVITY DATA
# ============================================================

activity_history = [

    (
        "✓",
        "Registry Scan Completed",
        "No suspicious patterns detected",
        GREEN
    ),

    (
        "✓",
        "Integrity Check",
        "Registry is unchanged",
        BLUE
    ),

    (
        "●",
        "Security Monitor",
        "System ready for monitoring",
        YELLOW
    )
]


# ============================================================
# HELPER - GET REGISTRY ENTRIES
# ============================================================

def get_all_registry_entries():

    user_entries = scan_registry(
        winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    system_entries = scan_registry(
        winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    test_entries = scan_registry(
        winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER",
        r"Software\WindowsRegistrySecurityMonitor\Test"
    )

    return user_entries + system_entries + test_entries


# ============================================================
# REGISTRY SCAN
# ============================================================

def scan_registry_gui():

    entries = get_all_registry_entries()

    suspicious_entries = []

    for entry in entries:

        reasons = analyze_entry(entry)

        if reasons:
            suspicious_entries.append(entry)

    suspicious_count = len(suspicious_entries)
    normal_count = len(entries) - suspicious_count

    # --------------------------------------------------------
    # Update statistics
    # --------------------------------------------------------

    total_card.config(
        text=str(len(entries))
    )

    normal_card.config(
        text=str(normal_count)
    )

    suspicious_card.config(
        text=str(suspicious_count)
    )

    # --------------------------------------------------------
    # Update security status
    # --------------------------------------------------------

    update_security_status(
        suspicious_count > 0
    )

    # --------------------------------------------------------
    # Update activity
    # --------------------------------------------------------

    if suspicious_count > 0:

        add_activity(
            "!",
            "Suspicious Activity Detected",
            f"{suspicious_count} suspicious registry entry found",
            RED
        )

    else:

        add_activity(
            "✓",
            "Registry Scan Completed",
            f"{len(entries)} registry entries scanned",
            GREEN
        )

    # --------------------------------------------------------
    # Popup
    # --------------------------------------------------------

    messagebox.showinfo(
        "Registry Scan",
        "Registry scan completed successfully!\n\n"
        f"Total Entries: {len(entries)}\n"
        f"Normal Entries: {normal_count}\n"
        f"Suspicious Entries: {suspicious_count}"
    )


# ============================================================
# INTEGRITY CHECK
# ============================================================

def check_integrity_gui():

    entries = get_all_registry_entries()

    changes = check_integrity(entries)

    changes_card.config(
        text=str(changes)
    )

    # --------------------------------------------------------
    # Update security status
    # --------------------------------------------------------

    if changes > 0:

        update_security_status(
            True,
            "Registry changes detected"
        )

        add_activity(
            "!",
            "Registry Changes Detected",
            f"{changes} registry changes detected",
            YELLOW
        )

    else:

        # Only show secure if no suspicious entries are known
        suspicious_count = 0

        for entry in entries:

            if analyze_entry(entry):
                suspicious_count += 1

        if suspicious_count > 0:

            update_security_status(
                True,
                "Suspicious registry activity detected"
            )

        else:

            update_security_status(
                False
            )

        add_activity(
            "✓",
            "Integrity Check",
            "Registry is unchanged",
            BLUE
        )

    messagebox.showinfo(
        "Integrity Check",
        "Registry integrity check completed!\n\n"
        f"Changes detected: {changes}\n\n"
        "Check the terminal for detailed results."
    )


# ============================================================
# GENERATE REPORT
# ============================================================

def generate_report_gui():

    entries = get_all_registry_entries()

    generate_report(entries)

    add_activity(
        "✓",
        "Security Report Generated",
        "Registry security report created",
        GREEN
    )

    open_report_viewer()


# ============================================================
# REPORT VIEWER
# ============================================================

def open_report_viewer():

    report_file = "reports/registry_report.txt"

    try:

        with open(
            report_file,
            "r"
        ) as file:

            report_content = file.read()

    except FileNotFoundError:

        messagebox.showwarning(
            "Report Not Found",
            "No security report has been generated yet."
        )

        return

    report_window = tk.Toplevel(root)

    report_window.title(
        "Security Report"
    )

    report_window.geometry(
        "850x650"
    )

    report_window.configure(
        bg=BG
    )

    report_window.minsize(
        700,
        500
    )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    header = tk.Frame(
        report_window,
        bg=BG
    )

    header.pack(
        fill="x",
        padx=25,
        pady=(20, 10)
    )

    tk.Label(
        header,
        text="Security Report",
        font=("Arial", 20, "bold"),
        bg=BG,
        fg=TEXT
    ).pack(
        side="left"
    )

    tk.Label(
        header,
        text="Windows Registry Security Analysis",
        font=("Arial", 9),
        bg=BG,
        fg=MUTED
    ).pack(
        side="left",
        padx=15,
        pady=8
    )

    # --------------------------------------------------------
    # Report area
    # --------------------------------------------------------

    report_frame = tk.Frame(
        report_window,
        bg=CARD
    )

    report_frame.pack(
        fill="both",
        expand=True,
        padx=25,
        pady=(5, 20)
    )

    scrollbar = tk.Scrollbar(
        report_frame
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    report_text = tk.Text(
        report_frame,
        font=("Consolas", 10),
        bg="#0f172a",
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        bd=0,
        padx=18,
        pady=18,
        wrap="word",
        yscrollcommand=scrollbar.set
    )

    report_text.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.config(
        command=report_text.yview
    )

    report_text.insert(
        "1.0",
        report_content
    )

    report_text.config(
        state="disabled"
    )

    # --------------------------------------------------------
    # Close button
    # --------------------------------------------------------

    tk.Button(
        report_window,
        text="CLOSE",
        font=("Arial", 10, "bold"),
        bg=CARD2,
        fg=TEXT,
        activebackground=BLUE,
        activeforeground="#000000",
        relief="flat",
        bd=0,
        padx=25,
        pady=10,
        cursor="hand2",
        command=report_window.destroy
    ).pack(
        pady=(0, 20)
    )


# ============================================================
# SECURITY STATUS UPDATE
# ============================================================

def update_security_status(
    problem_detected=False,
    custom_message=None
):

    if problem_detected:

        status_label.config(
            text="●  REVIEW REQUIRED",
            fg=RED,
            bg="#3a1717"
        )

        security_status.config(
            bg="#3a1717"
        )

        security_icon.config(
            text="!",
            fg=RED,
            bg="#3a1717"
        )

        security_status_text.config(
            text=custom_message
            if custom_message
            else "Suspicious activity detected",
            fg=RED
        )

        health_fill.config(
            bg=RED
        )

        health_status_label.config(
            text="Review Required",
            fg=RED
        )

    else:

        status_label.config(
            text="●  SYSTEM SECURE",
            fg=GREEN,
            bg="#12351f"
        )

        security_status.config(
            bg="#12351f"
        )

        security_icon.config(
            text="✓",
            fg=GREEN,
            bg="#12351f"
        )

        security_status_text.config(
            text="No suspicious activity detected",
            fg=MUTED
        )

        health_fill.config(
            bg=GREEN
        )

        health_status_label.config(
            text="Healthy",
            fg=GREEN
        )


# ============================================================
# START MONITOR
# ============================================================

def start_monitor_gui():

    global monitor_process

    if monitor_process and monitor_process.poll() is None:

        messagebox.showinfo(
            "Monitor",
            "Monitoring is already running."
        )

        return

    try:

        monitor_process = subprocess.Popen(
            ["python", "monitor.py"]
        )

    except Exception as error:

        messagebox.showerror(
            "Monitor Error",
            f"Unable to start monitoring.\n\n{error}"
        )

        return

    add_activity(
        "●",
        "Security Monitor",
        "Continuous monitoring started",
        GREEN
    )

    monitor_status_label.config(
        text="MONITORING ACTIVE",
        fg=GREEN
    )

    messagebox.showinfo(
        "Monitor Started",
        "Continuous Registry Monitoring has started."
    )


# ============================================================
# STOP MONITOR
# ============================================================

def stop_monitor_gui():

    global monitor_process

    if monitor_process and monitor_process.poll() is None:

        monitor_process.terminate()

        monitor_process = None

        add_activity(
            "■",
            "Security Monitor",
            "Continuous monitoring stopped",
            RED
        )

        monitor_status_label.config(
            text="MONITOR STOPPED",
            fg=MUTED
        )

        messagebox.showinfo(
            "Monitor Stopped",
            "Continuous Registry Monitoring has been stopped."
        )

    else:

        monitor_status_label.config(
            text="MONITOR STOPPED",
            fg=MUTED
        )

        messagebox.showinfo(
            "Monitor",
            "Monitoring is not running."
        )


# ============================================================
# SETTINGS WINDOW
# ============================================================

def open_settings():

    settings_window = tk.Toplevel(root)

    settings_window.title(
        "Settings"
    )

    settings_window.geometry(
        "500x430"
    )

    settings_window.configure(
        bg=BG
    )

    settings_window.resizable(
        False,
        False
    )

    tk.Label(
        settings_window,
        text="Application Settings",
        font=("Arial", 20, "bold"),
        bg=BG,
        fg=TEXT
    ).pack(
        anchor="w",
        padx=30,
        pady=(25, 5)
    )

    tk.Label(
        settings_window,
        text="Windows Registry Security Monitor configuration",
        font=("Arial", 9),
        bg=BG,
        fg=MUTED
    ).pack(
        anchor="w",
        padx=30
    )

    settings_card = tk.Frame(
        settings_window,
        bg=CARD
    )

    settings_card.pack(
        fill="both",
        expand=True,
        padx=30,
        pady=25
    )

    settings = [

        (
            "Application",
            "Windows Registry Security Monitor"
        ),

        (
            "Monitoring",
            "Local Windows Registry"
        ),

        (
            "Monitor Interval",
            "5 seconds"
        ),

        (
            "Database",
            "SQLite"
        ),

        (
            "Report Location",
            "reports/registry_report.txt"
        ),

        (
            "Version",
            "1.0"
        )
    ]

    for label, value in settings:

        row = tk.Frame(
            settings_card,
            bg=CARD
        )

        row.pack(
            fill="x",
            padx=20,
            pady=10
        )

        tk.Label(
            row,
            text=label,
            font=("Arial", 9, "bold"),
            bg=CARD,
            fg=MUTED,
            width=18,
            anchor="w"
        ).pack(
            side="left"
        )

        tk.Label(
            row,
            text=value,
            font=("Arial", 9),
            bg=CARD,
            fg=TEXT,
            anchor="w"
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

    tk.Button(
        settings_window,
        text="CLOSE",
        font=("Arial", 10, "bold"),
        bg=CARD2,
        fg=TEXT,
        activebackground=BLUE,
        activeforeground="#000000",
        relief="flat",
        bd=0,
        padx=25,
        pady=10,
        cursor="hand2",
        command=settings_window.destroy
    ).pack(
        pady=(0, 25)
    )


# ============================================================
# WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "Windows Registry Security Monitor"
)

root.geometry(
    "1150x850"
)

root.minsize(
    1000,
    650
)

root.configure(
    bg=BG
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

try:

    create_database()

except Exception as error:

    print(
        f"Database initialization warning: {error}"
    )


# ============================================================
# SIDEBAR
# ============================================================

sidebar = tk.Frame(
    root,
    bg=SIDEBAR,
    width=235
)

sidebar.pack(
    side="left",
    fill="y"
)

sidebar.pack_propagate(False)


# ------------------------------------------------------------
# Logo
# ------------------------------------------------------------

logo_box = tk.Frame(
    sidebar,
    bg="#16243a",
    width=58,
    height=58
)

logo_box.pack(
    pady=(30, 10)
)

logo_box.pack_propagate(False)

logo = tk.Label(
    logo_box,
    text="🛡",
    font=("Segoe UI Emoji", 27),
    bg="#16243a",
    fg=BLUE
)

logo.pack(
    expand=True
)


app_title = tk.Label(
    sidebar,
    text="REGISTRY\nSECURITY MONITOR",
    font=("Segoe UI", 13, "bold"),
    bg=SIDEBAR,
    fg=TEXT,
    justify="center"
)

app_title.pack(
    pady=(0, 35)
)


# ============================================================
# NAVIGATION
# ============================================================

nav_title = tk.Label(
    sidebar,
    text="MAIN MENU",
    font=("Arial", 8, "bold"),
    bg=SIDEBAR,
    fg="#64748b"
)

nav_title.pack(
    anchor="w",
    padx=25,
    pady=(0, 8)
)


def nav_button(
    text,
    active=False
):

    button_bg = (
        "#1e3a56"
        if active
        else SIDEBAR
    )

    button_fg = (
        BLUE
        if active
        else MUTED
    )

    return tk.Button(
        sidebar,
        text=text,
        font=("Arial", 10, "bold"),
        bg=button_bg,
        fg=button_fg,
        activebackground="#1e3a56",
        activeforeground=BLUE,
        relief="flat",
        bd=0,
        anchor="w",
        padx=22,
        pady=13,
        cursor="hand2"
    )


# Dashboard

dashboard_btn = nav_button(
    "▣    Dashboard",
    True
)

dashboard_btn.config(
    command=lambda: None
)

dashboard_btn.pack(
    fill="x",
    padx=12,
    pady=3
)


# Registry Scan

scan_btn = nav_button(
    "⌕    Registry Scan"
)

scan_btn.config(
    command=scan_registry_gui
)

scan_btn.pack(
    fill="x",
    padx=12,
    pady=3
)


# Live Monitor

monitor_btn = nav_button(
    "◉    Live Monitor"
)

monitor_btn.config(
    command=start_monitor_gui
)

monitor_btn.pack(
    fill="x",
    padx=12,
    pady=3
)


# Security Reports

report_btn = nav_button(
    "▤    Security Reports"
)

report_btn.config(
    command=generate_report_gui
)

report_btn.pack(
    fill="x",
    padx=12,
    pady=3
)


# Settings

settings_btn = nav_button(
    "⚙    Settings"
)

settings_btn.config(
    command=open_settings
)

settings_btn.pack(
    fill="x",
    padx=12,
    pady=3
)


# ============================================================
# SIDEBAR BOTTOM
# ============================================================

bottom = tk.Frame(
    sidebar,
    bg=SIDEBAR
)

bottom.pack(
    side="bottom",
    fill="x",
    pady=25
)


version = tk.Label(
    bottom,
    text="Windows Security Tool\nVersion 1.0",
    font=("Arial", 8),
    bg=SIDEBAR,
    fg="#64748b",
    justify="center"
)

version.pack()


# ============================================================
# MAIN CONTENT
# ============================================================

main = tk.Frame(
    root,
    bg=BG
)

main.pack(
    side="left",
    fill="both",
    expand=True
)


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    main,
    bg=BG
)

header.pack(
    fill="x",
    padx=35,
    pady=(28, 5)
)


heading = tk.Label(
    header,
    text="Security Dashboard",
    font=("Arial", 25, "bold"),
    bg=BG,
    fg=TEXT
)

heading.pack(
    side="left"
)


# Security status

security_status = tk.Frame(
    header,
    bg="#12351f",
    padx=14,
    pady=8
)

security_status.pack(
    side="right"
)


status_label = tk.Label(
    security_status,
    text="●  SYSTEM SECURE",
    font=("Arial", 9, "bold"),
    bg="#12351f",
    fg=GREEN
)

status_label.pack()


# Monitor status

monitor_status_label = tk.Label(
    header,
    text="MONITOR STOPPED",
    font=("Arial", 8, "bold"),
    bg=BG,
    fg=MUTED
)

monitor_status_label.pack(
    side="right",
    padx=15
)


subtitle = tk.Label(
    main,
    text=(
        "Monitor registry activity, detect suspicious entries "
        "and verify system integrity."
    ),
    font=("Arial", 10),
    bg=BG,
    fg=MUTED
)

subtitle.pack(
    anchor="w",
    padx=35
)


# ============================================================
# STATISTICS
# ============================================================

stats = tk.Frame(
    main,
    bg=BG
)

stats.pack(
    fill="x",
    padx=28,
    pady=25
)


def create_stat_card(
    parent,
    title,
    value,
    description,
    accent
):

    card = tk.Frame(
        parent,
        bg=CARD,
        height=125
    )

    card.pack(
        side="left",
        fill="both",
        expand=True,
        padx=7
    )

    card.pack_propagate(False)


    line = tk.Frame(
        card,
        bg=accent,
        width=4
    )

    line.pack(
        side="left",
        fill="y"
    )


    content = tk.Frame(
        card,
        bg=CARD
    )

    content.pack(
        fill="both",
        expand=True,
        padx=18
    )


    tk.Label(
        content,
        text=title,
        font=("Arial", 9),
        bg=CARD,
        fg=MUTED
    ).pack(
        anchor="w",
        pady=(18, 2)
    )


    value_label = tk.Label(
        content,
        text=value,
        font=("Arial", 25, "bold"),
        bg=CARD,
        fg=accent
    )

    value_label.pack(
        anchor="w"
    )


    tk.Label(
        content,
        text=description,
        font=("Arial", 8),
        bg=CARD,
        fg="#64748b"
    ).pack(
        anchor="w"
    )


    return value_label


total_card = create_stat_card(
    stats,
    "REGISTRY ENTRIES",
    "0",
    "Entries scanned",
    BLUE
)


normal_card = create_stat_card(
    stats,
    "NORMAL",
    "0",
    "No suspicious pattern",
    GREEN
)


suspicious_card = create_stat_card(
    stats,
    "SUSPICIOUS",
    "0",
    "Requires review",
    RED
)


changes_card = create_stat_card(
    stats,
    "CHANGES",
    "0",
    "Integrity changes",
    YELLOW
)


# ============================================================
# LOWER SECTION
# ============================================================

lower = tk.Frame(
    main,
    bg=BG,
    height=410
)

lower.pack(
    fill="x",
    padx=35,
    pady=(0, 10)
)

lower.pack_propagate(False)


# ============================================================
# SECURITY OVERVIEW
# ============================================================

security_card = tk.Frame(
    lower,
    bg=CARD
)

security_card.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 8)
)


tk.Label(
    security_card,
    text="Security Overview",
    font=("Arial", 15, "bold"),
    bg=CARD,
    fg=TEXT
).pack(
    anchor="w",
    padx=22,
    pady=(20, 3)
)


tk.Label(
    security_card,
    text="Current Registry Protection Status",
    font=("Arial", 9),
    bg=CARD,
    fg=MUTED
).pack(
    anchor="w",
    padx=22
)


security_box = tk.Frame(
    security_card,
    bg=CARD
)

security_box.pack(
    pady=20
)


security_icon = tk.Label(
    security_box,
    text="✓",
    font=("Arial", 30, "bold"),
    bg="#12351f",
    fg=GREEN,
    width=3,
    height=1
)

security_icon.pack(
    side="left",
    padx=15
)


security_text = tk.Frame(
    security_box,
    bg=CARD
)

security_text.pack(
    side="left"
)


security_title = tk.Label(
    security_text,
    text="System Secure",
    font=("Arial", 13, "bold"),
    bg=CARD,
    fg=GREEN
)

security_title.pack(
    anchor="w"
)


security_status_text = tk.Label(
    security_text,
    text="No suspicious activity detected",
    font=("Arial", 9),
    bg=CARD,
    fg=MUTED
)

security_status_text.pack(
    anchor="w"
)


# ============================================================
# REGISTRY HEALTH
# ============================================================

tk.Label(
    security_card,
    text="Registry Health",
    font=("Arial", 9, "bold"),
    bg=CARD,
    fg=TEXT
).pack(
    anchor="w",
    padx=22
)


health_bar = tk.Frame(
    security_card,
    bg="#263449",
    height=9
)

health_bar.pack(
    fill="x",
    padx=22,
    pady=(7, 5)
)

health_bar.pack_propagate(False)


health_fill = tk.Frame(
    health_bar,
    bg=GREEN
)

health_fill.pack(
    side="left",
    fill="both",
    expand=True
)


health_status_label = tk.Label(
    security_card,
    text="Healthy",
    font=("Arial", 9, "bold"),
    bg=CARD,
    fg=GREEN
)

health_status_label.pack(
    anchor="e",
    padx=22
)


# ============================================================
# RECENT ACTIVITY
# ============================================================

activity_card = tk.Frame(
    lower,
    bg=CARD
)

activity_card.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(8, 0)
)


tk.Label(
    activity_card,
    text="Recent Activity",
    font=("Arial", 15, "bold"),
    bg=CARD,
    fg=TEXT
).pack(
    anchor="w",
    padx=22,
    pady=(18, 2)
)


tk.Label(
    activity_card,
    text="Latest system activities",
    font=("Arial", 9),
    bg=CARD,
    fg=MUTED
).pack(
    anchor="w",
    padx=22
)


# ============================================================
# ACTIVITY ROW
# ============================================================

def activity_row(
    parent,
    icon,
    title,
    detail,
    color
):

    row = tk.Frame(
        parent,
        bg=CARD2
    )

    row.pack(
        fill="x",
        padx=18,
        pady=5
    )


    tk.Label(
        row,
        text=icon,
        font=("Arial", 11, "bold"),
        bg=CARD2,
        fg=color,
        width=3
    ).pack(
        side="left",
        padx=4
    )


    info = tk.Frame(
        row,
        bg=CARD2
    )

    info.pack(
        side="left",
        fill="x",
        expand=True,
        pady=7
    )


    tk.Label(
        info,
        text=title,
        font=("Arial", 8, "bold"),
        bg=CARD2,
        fg=TEXT
    ).pack(
        anchor="w"
    )


    tk.Label(
        info,
        text=detail,
        font=("Arial", 7),
        bg=CARD2,
        fg=MUTED
    ).pack(
        anchor="w"
    )


# ============================================================
# ACTIVITY CONTAINER
# ============================================================

activity_rows_frame = tk.Frame(
    activity_card,
    bg=CARD
)

activity_rows_frame.pack(
    fill="x",
    pady=(8, 0)
)


def refresh_activity():

    for widget in activity_rows_frame.winfo_children():

        widget.destroy()


    for icon, title, detail, color in activity_history[:3]:

        activity_row(
            activity_rows_frame,
            icon,
            title,
            detail,
            color
        )


def add_activity(
    icon,
    title,
    detail,
    color
):

    activity_history.insert(
        0,
        (
            icon,
            title,
            detail,
            color
        )
    )

    refresh_activity()


# ============================================================
# RECENT SECURITY EVENTS
# ============================================================

database_events_card = tk.Frame(
    activity_card,
    bg=CARD
)

database_events_card.pack(
    fill="x",
    padx=18,
    pady=(10, 0)
)


tk.Label(
    database_events_card,
    text="Recent Security Events",
    font=("Arial", 10, "bold"),
    bg=CARD,
    fg=TEXT
).pack(
    anchor="w",
    padx=5,
    pady=(2, 1)
)


tk.Label(
    database_events_card,
    text="Events recorded in security database",
    font=("Arial", 7),
    bg=CARD,
    fg=MUTED
).pack(
    anchor="w",
    padx=5
)


database_rows_frame = tk.Frame(
    database_events_card,
    bg=CARD
)

database_rows_frame.pack(
    fill="x",
    pady=(5, 0)
)


last_database_events = None


def load_database_events():

    global last_database_events

    try:

        events = get_events()

    except Exception:

        events = []


    latest_events = events[:3]

    current_state = tuple(
        latest_events
    )


    if current_state != last_database_events:

        last_database_events = current_state


        for widget in database_rows_frame.winfo_children():

            widget.destroy()


        if not latest_events:

            tk.Label(
                database_rows_frame,
                text="No security events recorded",
                font=("Arial", 7),
                bg=CARD,
                fg=MUTED
            ).pack(
                anchor="w",
                padx=5,
                pady=5
            )


        else:

            for event in latest_events:

                (
                    event_type,
                    event_root,
                    registry_path,
                    name,
                    value,
                    timestamp
                ) = event


                if event_type == "NEW":

                    icon = "+"
                    color = GREEN


                elif event_type == "MODIFIED":

                    icon = "*"
                    color = YELLOW


                elif event_type == "DELETED":

                    icon = "-"
                    color = RED


                else:

                    icon = "•"
                    color = BLUE


                row = tk.Frame(
                    database_rows_frame,
                    bg=CARD2
                )

                row.pack(
                    fill="x",
                    pady=2
                )


                tk.Label(
                    row,
                    text=icon,
                    font=("Arial", 8, "bold"),
                    bg=CARD2,
                    fg=color,
                    width=2
                ).pack(
                    side="left",
                    padx=4
                )


                tk.Label(
                    row,
                    text=event_type,
                    font=("Arial", 7, "bold"),
                    bg=CARD2,
                    fg=color
                ).pack(
                    side="left"
                )


                tk.Label(
                    row,
                    text=name,
                    font=("Arial", 7),
                    bg=CARD2,
                    fg=TEXT
                ).pack(
                    side="left",
                    padx=7
                )


                tk.Label(
                    row,
                    text=timestamp,
                    font=("Arial", 6),
                    bg=CARD2,
                    fg=MUTED
                ).pack(
                    side="right",
                    padx=6
                )


    root.after(
        2000,
        load_database_events
    )


# ============================================================
# INITIAL DISPLAY
# ============================================================

refresh_activity()

load_database_events()


# ============================================================
# ACTION BUTTONS
# ============================================================

actions = tk.Frame(
    main,
    bg=BG
)

actions.pack(
    fill="x",
    padx=35,
    pady=(0, 15)
)


def action_button(
    parent,
    text,
    accent
):

    return tk.Button(
        parent,
        text=text,
        font=("Arial", 10, "bold"),
        bg=CARD2,
        fg=TEXT,
        activebackground=accent,
        activeforeground="#000000",
        relief="flat",
        bd=0,
        padx=12,
        pady=14,
        cursor="hand2"
    )


# Scan

scan_action = action_button(
    actions,
    "⌕  SCAN REGISTRY",
    BLUE
)

scan_action.config(
    command=scan_registry_gui
)

scan_action.pack(
    side="left",
    fill="x",
    expand=True,
    padx=(0, 5)
)


# Integrity

integrity_action = action_button(
    actions,
    "✓  CHECK INTEGRITY",
    GREEN
)

integrity_action.config(
    command=check_integrity_gui
)

integrity_action.pack(
    side="left",
    fill="x",
    expand=True,
    padx=5
)


# Report

report_action = action_button(
    actions,
    "▤  GENERATE REPORT",
    YELLOW
)

report_action.config(
    command=generate_report_gui
)

report_action.pack(
    side="left",
    fill="x",
    expand=True,
    padx=5
)


# Start Monitor

monitor_action = action_button(
    actions,
    "◉  START MONITOR",
    BLUE
)

monitor_action.config(
    command=start_monitor_gui
)

monitor_action.pack(
    side="left",
    fill="x",
    expand=True,
    padx=5
)


# Stop Monitor

stop_action = action_button(
    actions,
    "■  STOP MONITOR",
    RED
)

stop_action.config(
    command=stop_monitor_gui
)

stop_action.pack(
    side="left",
    fill="x",
    expand=True,
    padx=(5, 0)
)


# ============================================================
# FOOTER
# ============================================================

footer = tk.Label(
    main,
    text=(
        "Windows Registry Security Monitor  •  "
        "Local Security Analysis Tool  •  v1.0"
    ),
    font=("Arial", 8),
    bg=BG,
    fg="#526176"
)

footer.pack(
    pady=(0, 8)
)


# ============================================================
# RUN
# ============================================================

root.mainloop()