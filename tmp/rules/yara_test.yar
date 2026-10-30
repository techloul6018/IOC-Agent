rule test_yara_rule
{
    strings:
        $a = "a"
    condition:
        true
}