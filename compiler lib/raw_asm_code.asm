//fonction de copie asm ascii utf-16

    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rdi, rdx

    test r8, r8
    jnz skip_strlen
    mov rax, $asm_strlen
    call rax
    mov r8, rax
skip_strlen:

    mov rsi, rcx
    xor rcx, rcx

ascii_to_utf16_loop:
    cmp rcx, r8
    jae ascii_done

    mov al, byte ptr [rsi+rcx]
    test al, al
    jz ascii_done

    mov byte ptr [rdi], al
    inc rdi
    mov byte ptr [rdi], 0
    inc rdi

    inc rcx
    jmp ascii_to_utf16_loop

ascii_done:
    mov word ptr [rdi], 0

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
