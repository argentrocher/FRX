ASM64CPP

; compiler avec:  asm_cpp64 dll_test1.asm dll_test1.dll --dll

;
; ce code en utilisant la fonction view affiche l'ensemble des tampons lors de l'appel (sauf les xmm plus grand que 1)
;

include defaut:

global DllMain :                        ; deglaration du nom du point d'entrer fichier (de base main )

section .data

buffer affiche_buf 20
ascii end_line "\n"
ascii _rsp "rsp:\t"
ascii _rax "rax:\t"
ascii _rcx "rcx:\t"
ascii _rdx "rdx:\t"
ascii _rbx "rbx:\t"
ascii _rsi "rsi:\t"
ascii _rdi "rdi:\t"
ascii _r8 "r8:\t"
ascii _r9 "r9:\t"
ascii _r10 "r10:\t"
ascii _r11 "r11:\t"
ascii _r12 "r12:\t"
ascii _r13 "r13:\t"
ascii _r14 "r14:\t"
ascii _r15 "r15:\t"
ascii _xmm0 "xmm0:\t"
ascii _xmm1 "xmm1:\t"

section .edata

extern print msvcrt.printf
local view

section .idata

kernel32.dll ExitProcess 
msvcrt.dll printf

section .text

;code lancer par défaut en dll en mettant ce code a entrypoint
proc DllMain
    mov eax, 1
    ret
end DllMain

proc view
	sub rsp, 98h
	movdqu [rsp+88h], xmm0
	movdqu [rsp+78h], xmm1
	mov [rsp+70h], r8
	mov [rsp+68h], r9
	mov [rsp+60h], r10
	mov [rsp+58h], r11
	mov [rsp+50h], r12
	mov [rsp+48h], r13
	mov [rsp+40h], r14
	mov [rsp+38h], r15
	mov [rsp+30h], rcx
	mov [rsp+28h], rdx
    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi
	mov [rsp+8h], rax
	
	lea rcx, [rip+@_rsp]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, rsp
	add rcx, 98h
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rax]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+8h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rcx]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+30h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rdx]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+28h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rbx]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+20h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rsi]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+18h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_rdi]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+10h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r8]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+70h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r9]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+68h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r10]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+60h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r11]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+58h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r12]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+50h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r13]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+48h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r14]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+40h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_r15]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+38h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_xmm0]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+88h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+90h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@_xmm1]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+78h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	mov rcx, [rsp+80h]
	lea rax, [rip+@asm_addr_ascii]
	mov r8, 0
	lea rdx, [rip+@affiche_buf]
	call rax
	
	lea rcx, [rip+@affiche_buf]
	mov rax, [rip+@printf]
    call rax
	
	lea rcx, [rip+@end_line]
	mov rax, [rip+@printf]
    call rax
	
	movdqu xmm0, [rsp+88h]
	movdqu xmm1, [rsp+78h]
	mov r8, [rsp+70h]
	mov r9, [rsp+68h]
	mov rcx, [rsp+30h]
	mov rdx, [rsp+28h]
	mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]
    add rsp, 98h
	
	mov rax, rcx
	
    ret
end view

; il est possible d'ajouter les autres tampons xmm jusqu'à 15 si besoin

proc exit
        sub rsp, 28h
        xor ecx, ecx
        lea rax, [rip+@ExitProcess]
        mov rax, [rax]
        call rax
        add rsp, 28h
        ret
end exit

; end
