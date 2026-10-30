rule Simple_Test
{
    strings:
        $a = "encodedCommand"
        $b = "AMSIbypass"
    condition:
        2 of them