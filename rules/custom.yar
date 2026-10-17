/*
  Malvexis starter rules. Add your own here - one rule per behaviour, with meta:
    description  - shown in reports
    severity     - low | medium | high | critical (drives the score)
*/

rule EICAR_Test_File
{
    meta:
        description = "Standard anti-virus test file (harmless)"
        author = "Malvexis"
        severity = "critical"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar and filesize < 1KB
}

rule PE_UPX_Packed
{
    meta:
        description = "PE file packed with UPX (legitimate software uses it too)"
        author = "Malvexis"
        severity = "low"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Process_Injection_APIs
{
    meta:
        description = "PE references the classic remote-thread injection API trio"
        author = "Malvexis"
        severity = "medium"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Script_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell download-and-execute pattern"
        author = "Malvexis"
        severity = "medium"
    strings:
        $ps  = "powershell" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $ex1 = "Invoke-Expression" ascii wide nocase
        $ex2 = "IEX" ascii wide
        $b64 = "FromBase64String" ascii wide nocase
    condition:
        $ps and (1 of ($dl*)) and (1 of ($ex*, $b64))
}
