rule Test_Basic
{
    strings:
        $s1 = "hello"
    condition:
        $s1
}