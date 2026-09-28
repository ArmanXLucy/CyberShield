rule CyberShield_PDF_Active_Content
{
    strings:
        $a = "/JavaScript" ascii nocase
        $b = "/OpenAction" ascii nocase
        $c = "/Launch" ascii nocase
        $d = "/AA" ascii nocase
    condition:
        2 of them
}

