/*
    Wireshark MCP — Built-in YARA rules for exported file scanning.
    Users can add custom rules to ~/.wireshark-mcp/yara/*.yar
*/

rule PE_Executable
{
    meta:
        description = "Windows PE executable (MZ header)"
        severity = "medium"
        category = "executable"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
    condition:
        $mz at 0 and $pe
}

rule ELF_Executable
{
    meta:
        description = "Linux ELF executable"
        severity = "medium"
        category = "executable"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule Mach_O_Executable
{
    meta:
        description = "macOS Mach-O executable"
        severity = "medium"
        category = "executable"
    strings:
        $macho1 = { FE ED FA CE }
        $macho2 = { FE ED FA CF }
        $macho3 = { CE FA ED FE }
        $macho4 = { CF FA ED FE }
    condition:
        any of them at 0
}

rule Shellcode_NOP_Sled
{
    meta:
        description = "Potential NOP sled (shellcode indicator)"
        severity = "high"
        category = "shellcode"
    strings:
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop16
}

rule Shellcode_Common_Patterns
{
    meta:
        description = "Common x86/x64 shellcode patterns"
        severity = "high"
        category = "shellcode"
    strings:
        $syscall_x86 = { CD 80 }
        $syscall_x64 = { 0F 05 }
        $int2e = { CD 2E }
        $call_esp = { FF D4 }
        $jmp_esp = { FF E4 }
        $call_eax = { FF D0 }
    condition:
        2 of them
}

rule Webshell_PHP
{
    meta:
        description = "PHP webshell indicators"
        severity = "critical"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $system = "system(" nocase
        $passthru = "passthru(" nocase
        $shell_exec = "shell_exec(" nocase
        $base64 = "base64_decode(" nocase
        $assert = "assert(" nocase
        $preg_replace_e = "/e\"" nocase
    condition:
        $php and 2 of ($eval, $exec, $system, $passthru, $shell_exec, $base64, $assert, $preg_replace_e)
}

rule Webshell_JSP
{
    meta:
        description = "JSP webshell indicators"
        severity = "critical"
        category = "webshell"
    strings:
        $runtime = "Runtime.getRuntime()" nocase
        $processbuilder = "ProcessBuilder" nocase
        $exec = ".exec(" nocase
        $cmd = "cmd.exe" nocase
        $bash = "/bin/bash" nocase
    condition:
        any of ($runtime, $processbuilder) and any of ($exec, $cmd, $bash)
}

rule Webshell_ASP
{
    meta:
        description = "ASP/ASPX webshell indicators"
        severity = "critical"
        category = "webshell"
    strings:
        $execute = "Execute(" nocase
        $eval = "Eval(" nocase
        $wscript = "WScript.Shell" nocase
        $process = "System.Diagnostics.Process" nocase
        $cmd = "cmd /c" nocase
    condition:
        2 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Obfuscated or suspicious PowerShell command"
        severity = "high"
        category = "script"
    strings:
        $enc_cmd = "-EncodedCommand" nocase ascii wide
        $enc_short = "-enc " nocase ascii wide
        $bypass = "-ExecutionPolicy Bypass" nocase ascii wide
        $hidden = "-WindowStyle Hidden" nocase ascii wide
        $noprofile = "-NoProfile" nocase ascii wide
        $iex = "IEX(" nocase ascii wide
        $invoke = "Invoke-Expression" nocase ascii wide
        $download = "DownloadString(" nocase ascii wide
        $webclient = "Net.WebClient" nocase ascii wide
    condition:
        2 of them
}

rule Base64_Encoded_PE
{
    meta:
        description = "Base64-encoded PE executable in text content"
        severity = "high"
        category = "encoded_payload"
    strings:
        $b64_mz = "TVqQAA" ascii wide
        $b64_mz2 = "TVpQAA" ascii wide
        $b64_mz3 = "TVoAAA" ascii wide
    condition:
        any of them
}

rule Suspicious_JavaScript
{
    meta:
        description = "Potentially malicious JavaScript patterns"
        severity = "medium"
        category = "script"
    strings:
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcharcode = "fromCharCode" nocase
        $activex = "ActiveXObject" nocase
        $wscript = "WScript" nocase
        $shell = "Shell.Application" nocase
    condition:
        $eval and 2 of ($unescape, $fromcharcode, $activex, $wscript, $shell)
}

rule Packed_UPX
{
    meta:
        description = "UPX packed executable"
        severity = "low"
        category = "packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        2 of them
}
