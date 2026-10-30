rule PowerShell_Obfuscation_AMSI_Bypass
{
    strings:
        $encoded_cmd = "encodedCommand"
        $amsi_bypass = "AMSIbypass"
        $ref_assembly = "[Ref].Assembly"
        $amsi_init = "amsiInitFile"
    condition:
        2 of them
}