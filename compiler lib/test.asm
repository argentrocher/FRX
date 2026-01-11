ASM64CPP
//asm_cpp64 test.asm bob.exe --see_all_exception --cmd

section .rsrc
icon "frx.ico"
version_simple "1.0.0.0" "MonApp.exe" "2026Moi"

section .data

utf16 msgutf16 "hello\n"
ascii msg "hello !\n"
buffer xxx 256

section .idata

kernel32.dll ExitProcess 
msvcrt.dll printf

section .text

proc main
        mov rax, $print
        call rax
        mov rax, $exit
        call rax
        ret
end main

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

