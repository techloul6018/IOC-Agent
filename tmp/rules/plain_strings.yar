rule test_yara_rule
{
    strings:
        $encoded_cmd = "encodedCommand"
        $amsi_bypass = "AMSIbypass"
    condition:
        2 of them
}