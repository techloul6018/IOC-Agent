rule Test_Format
{
    strings:
        $s1 = "hello"
    condition:
        $s1 == "hello"
}