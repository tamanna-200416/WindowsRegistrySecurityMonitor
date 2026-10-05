import winreg

TEST_PATH = r"Software\WindowsRegistrySecurityMonitor\Test"

key = winreg.CreateKey(
    winreg.HKEY_CURRENT_USER,
    TEST_PATH
)

winreg.SetValueEx(
    key,
    "SuspiciousTest",
    0,
    winreg.REG_SZ,
    r"C:\Users\DELL\AppData\Local\Temp\suspicious_test.bat"
)

winreg.CloseKey(key)

print("Safe suspicious test entry created successfully.")