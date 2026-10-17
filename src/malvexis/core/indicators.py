"""Shared indicator tables used by the strings, PE and scoring modules."""
from __future__ import annotations

# API name -> capability category. Heuristic only: many legitimate programs use these.
SUSPICIOUS_APIS: dict[str, str] = {
    # process injection / memory manipulation
    "VirtualAllocEx": "injection",
    "VirtualProtectEx": "injection",
    "WriteProcessMemory": "injection",
    "ReadProcessMemory": "injection",
    "CreateRemoteThread": "injection",
    "CreateRemoteThreadEx": "injection",
    "NtCreateThreadEx": "injection",
    "NtWriteVirtualMemory": "injection",
    "NtUnmapViewOfSection": "injection",
    "QueueUserAPC": "injection",
    "SetThreadContext": "injection",
    "RtlCreateUserThread": "injection",
    "VirtualAlloc": "memory",
    "VirtualProtect": "memory",
    "OpenProcess": "process",
    # anti-debugging / evasion
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "OutputDebugString": "anti_debug",
    "GetTickCount": "evasion",
    "NtDelayExecution": "evasion",
    # persistence / services
    "CreateService": "persistence",
    "StartService": "persistence",
    "RegSetValueEx": "persistence",
    "RegCreateKeyEx": "persistence",
    # keylogging / input capture
    "SetWindowsHookEx": "keylogging",
    "GetAsyncKeyState": "keylogging",
    "GetKeyboardState": "keylogging",
    "GetForegroundWindow": "keylogging",
    # networking / download
    "URLDownloadToFile": "network",
    "InternetOpen": "network",
    "InternetOpenUrl": "network",
    "InternetReadFile": "network",
    "HttpSendRequest": "network",
    "WSAStartup": "network",
    "connect": "network",
    "send": "network",
    "recv": "network",
    # crypto (ransomware-style capability when combined with file APIs)
    "CryptEncrypt": "crypto",
    "CryptAcquireContext": "crypto",
    "CryptGenKey": "crypto",
    "BCryptEncrypt": "crypto",
    # execution
    "WinExec": "execution",
    "ShellExecute": "execution",
    "CreateProcess": "execution",
    "CreateProcessAsUser": "execution",
    # privilege
    "AdjustTokenPrivileges": "privilege",
    "LookupPrivilegeValue": "privilege",
}

# Section name -> packer / protector
PACKER_SECTIONS: dict[str, str] = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".themida": "Themida",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".petite": "Petite",
    ".nsp0": "NsPack",
    ".nsp1": "NsPack",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
}

# Substrings that are interesting when found in extracted strings (matched case-insensitively)
SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "powershell",
    "cmd.exe /c",
    "frombase64string",
    "invoke-expression",
    "downloadstring",
    "wscript.shell",
    "regsvr32",
    "rundll32",
    "schtasks",
    "vssadmin delete",
    "bcdedit",
    "mimikatz",
    "net user",
    "certutil -urlcache",
)


def classify_api(name: str) -> str | None:
    """Return the capability category for an imported API name, or None.

    Handles the ANSI/Unicode suffix (CreateProcessA / CreateProcessW) and Nt/Zw aliases.
    """
    if not name:
        return None
    if name in SUSPICIOUS_APIS:
        return SUSPICIOUS_APIS[name]
    if name[-1] in ("A", "W") and name[:-1] in SUSPICIOUS_APIS:
        return SUSPICIOUS_APIS[name[:-1]]
    if name.startswith("Zw"):
        return SUSPICIOUS_APIS.get("Nt" + name[2:])
    return None
