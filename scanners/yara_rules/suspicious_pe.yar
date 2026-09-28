rule CyberShield_Suspicious_Windows_Command_And_PowerShell
{
    strings:
        $ps1 = "powershell.exe" ascii wide nocase
        $ps2 = "DownloadString" ascii wide nocase
        $cmd = "cmd.exe /c" ascii wide nocase
    condition:
        2 of them
}

