ASM64CPP
//blob

; asm_cpp64 test2.asm bob.exe --cmd

include default:

global hello :                        ; deglaration du nom du point d'entrer fichier (de base main )

section .rsrc
icon "frx.ico"                                                                       ; chemin de l'ico
version_simple "1.0.0.0" "MonApp.exe" "2026 \" Moi !"       ; version | nom de exe | copyright
manifest_simple "bob.exe" "1.0.0.0" false false false true   ; nom de exe | version | dpiAware | perMonitorV2 | requireAdmin | commonV6

; manifest_xml "contenu"  ; fait le manifest complet
; version_full fileVersion | productVersion | companyName | fileDescription | productName | originalFilename | copyright

section .data

utf16 msg "Hello convert !\n"
buffer tmpbuf 256


section .idata

kernel32.dll ExitProcess
msvcrt.dll wprintf


section .text

proc hello
    sub rsp, 28h

    ; asm_ascii_utf16(msg, tmpbuf, 0)
    mov rcx, 0x100000000014FF28
    mov rdx, $tmpbuf
    xor r8, r8
    mov rax, $asm_addr_utf16
    call rax

    ; wprintf(tmpbuf)
    mov rcx, $tmpbuf
    mov rax, $wprintf
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end hello


proc exit
    sub rsp, 30h
    xor ecx, ecx
    mov rax, $ExitProcess
    mov rax, [rax]
    call rax
    add rsp, 30h
    ret
end exit


;ok

