rule Minimal2
{
    strings:
        $s1 = "test"
    condition:
        $s1
}