rule VeryBasic
{
    strings:
        $s1 = "hello"
    condition:
        $s1
}