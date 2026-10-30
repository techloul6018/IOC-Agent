rule Test_Plain
{
    strings:
        $encoded_cmd = "encodedCommand"
    condition:
        true
}