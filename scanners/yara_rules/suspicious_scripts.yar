rule CyberShield_Suspicious_Script_Download_Exec
{
    strings:
        $a = "Invoke-WebRequest" ascii wide nocase
        $b = "DownloadString" ascii wide nocase
        $c = "FromBase64String" ascii wide nocase
        $d = "child_process" ascii wide nocase
        $e = "os.system(" ascii wide nocase
    condition:
        2 of them
}

