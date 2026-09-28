rule CyberShield_Archive_Executable_Name
{
    strings:
        $a = "invoice.exe" ascii wide nocase
        $b = "update.exe" ascii wide nocase
        $c = "keygen.exe" ascii wide nocase
    condition:
        1 of them
}

