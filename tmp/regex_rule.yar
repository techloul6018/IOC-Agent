rule Test_Regex
{
    strings:
        $encoded_cmd = /encodedCommand/
        $amsi_bypass = /AMSI.*bypass/
    condition:
        2 of them
}