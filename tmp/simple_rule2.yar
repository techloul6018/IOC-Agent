rule Simple_Test2
{
    strings:
        $a = "encodedCommand"
        $b = "AMSIbypass"
    condition:
        2 of them