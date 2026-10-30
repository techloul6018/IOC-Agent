rule Test_Plain_Strings
{
    strings:
        $s1 = "encodedCommand"
        $s2 = "AMSIbypass"
    condition:
        $s1 and $s2
}