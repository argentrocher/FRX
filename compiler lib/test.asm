;ASM64CPP
;please unquote the ASM64CPP

global hello :                        ; deglaration du nom du point d'entrer fichier (de base main )

section .rsrc
icon "frx.ico"                                                                       ; chemin de l'ico
version_simple "1.0.0.0" "MonApp.exe" "2026 \" Moi !"       ; version | nom de exe | copyright
manifest_simple "bob.exe" "1.0.0.0" false false false true   ; nom de exe | version | dpiAware | perMonitorV2 | requireAdmin | commonV6 

; manifest_xml "contenu"  ; fait le manifest complet
; version_full fileVersion | productVersion | companyName | fileDescription | productName | originalFilename | copyright

section .data

utf16 msgutf16 "hello\n"
ascii msg "hello !\n"
buffer xxx 256

section .idata

kernel32.dll ExitProcess 
msvcrt.dll printf

section .text

proc hello
        mov rax, $print
        call rax
        mov rax, $exit
        call rax
        ret
end hello

proc print
        sub rsp, 30h

        mov rcx, $msg
        mov rax, $printf
        mov rax, [rax]
        call rax

        add rsp, 30h
        ret
end print

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



