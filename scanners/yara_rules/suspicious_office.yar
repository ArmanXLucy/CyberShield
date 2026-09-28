rule CyberShield_Office_Macro_Indicators
{
    strings:
        $a = "vbaProject.bin" ascii wide nocase
        $b = "AutoOpen" ascii wide nocase
        $c = "Document_Open" ascii wide nocase
        $d = "Workbook_Open" ascii wide nocase
    condition:
        1 of them
}

