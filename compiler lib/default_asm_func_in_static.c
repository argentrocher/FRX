//fonction par defaut asm
void inject_default_asm_functions(GESTION& g)
{
    // strlen (exemple)
    // ; RCX = char*
    g.text_add_function("asm_strlen", R"(
    xor rax, rax

asm_strlen_loop:
    cmp byte ptr [rcx+rax], 0
    je asm_strlen_done
    inc rax
    jmp asm_strlen_loop

asm_strlen_done:
    ret
)");

    //; RCX = wchar_t* (UTF-16)
    g.text_add_function("asm_wstrlen", R"(
    xor rax, rax

.loop:
    mov dx, [rcx + rax*2]
    test dx, dx
    jz .done
    inc rax
    jmp .loop

.done:
    ret
)");

    //;copy tamp to tamp
    //; RCX = source
    //; RDX = destination
    //; r8 = taille de copy si != 0
    g.text_add_function("asm_copy", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rsi, rcx
    mov rdi, rdx
    xor rax, rax

    test r8, r8
    jnz .limited

.full_copy:
    mov bl, [rsi+rax]
    mov [rdi+rax], bl
    test bl, bl
    jz .done
    inc rax
    jmp .full_copy

.limited:
    cmp rax, r8
    jae .done
    mov bl, [rsi+rax]
    test bl, bl
    jz .done
    mov [rdi+rax], bl
    inc rax
    jmp .limited

.done:
    mov byte ptr [rdi+rax], 0

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //;copy tamp to tamp
    //; RCX = source (utf-16)
    //; RDX = destination (utf-16)
    //; r8 = taille de copy si != 0
    g.text_add_function("asm_wcopy", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rsi, rcx
    mov rdi, rdx
    xor rax, rax

    test r8, r8
    jnz .limited

.full_copy:
    mov bx, [rsi+rax*2]
    mov [rdi+rax*2], bx
    test bx, bx
    jz .done
    inc rax
    jmp .full_copy

.limited:
    cmp rax, r8
    jae .done
    mov bx, [rsi+rax*2]
    test bx, bx
    jz .done
    mov [rdi+rax*2], bx
    inc rax
    jmp .limited

.done:
    mov word ptr [rdi+rax*2], 0

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    g.text_add_function("asm_findstr", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi

    mov rsi, rcx
    mov rdi, rdx

    mov rcx, rdx
    mov rax, $asm_strlen
    call rax
    test rax, rax
    jz .not_found
    mov rcx, rsi
    mov rdx, rdi

.outer:
    mov al, [rsi]
    test al, al
    jz .not_found

    mov rcx, rsi
    mov rdx, rdi

.inner:
    mov al, [rdx]
    test al, al
    jz .found
    cmp al, [rcx]
    jne .next
    inc rcx
    inc rdx
    jmp .inner

.next:
    inc rsi
    jmp .outer

.found:
    mov eax, 1
    jmp .exit

.not_found:
    xor eax, eax

.exit:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    add rsp, 28h
    ret
)");

    g.text_add_function("asm_wfindstr", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi

    mov rsi, rcx
    mov rdi, rdx

    mov rcx, rdx
    mov rax, $asm_wstrlen
    call rax
    test rax, rax
    jz .not_found
    mov rcx, rsi
    mov rdx, rdi

.outer:
    mov ax, [rsi]
    test ax, ax
    jz .not_found

    mov rcx, rsi
    mov rdx, rdi

.inner:
    mov ax, [rdx]
    test ax, ax
    jz .found
    cmp ax, [rcx]
    jne .next
    add rcx, 2
    add rdx, 2
    jmp .inner

.next:
    add rsi, 2
    jmp .outer

.found:
    mov eax, 1
    jmp .exit

.not_found:
    xor eax, eax

.exit:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    add rsp, 28h
    ret
)");

    g.text_add_function("asm_strstr", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rsi, rcx
    mov rdi, rdx

    mov r8, rcx

    mov rcx, rdx
    mov rax, $asm_strlen
    call rax
    test rax, rax
    jz .not_found
    mov rcx, rsi
    mov rdx, rdi

    mov rbx, 0

.outer:
    mov al, [rsi]
    test al, al
    jz .not_found

    mov rcx, rsi
    mov rdx, rdi

.inner:
    mov al, [rdx]
    test al, al
    jz .found
    cmp al, [rcx]
    jne .next
    inc rcx
    inc rdx
    jmp .inner

.next:
    inc rsi
    inc rbx
    jmp .outer

.found:
    mov rcx, 1
    jmp .exit

.not_found:
    mov rcx, r8
    mov rax, $asm_strlen
    call rax
    mov rbx, rax

    xor rcx, rcx

.exit:
    mov rax, rbx

    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 28h
    ret
)");

    g.text_add_function("asm_wstrstr", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rsi, rcx
    mov rdi, rdx

    mov r8, rcx

    mov rcx, rdx
    mov rax, $asm_wstrlen
    call rax
    test rax, rax
    jz .not_found
    mov rcx, rsi
    mov rdx, rdi

    mov rbx, 0

.outer:
    mov ax, [rsi]
    test ax, ax
    jz .not_found

    mov rcx, rsi
    mov rdx, rdi

.inner:
    mov ax, [rdx]
    test ax, ax
    jz .found
    cmp ax, [rcx]
    jne .next
    add rcx, 2
    add rdx, 2
    jmp .inner

.next:
    add rsi, 2
    inc rbx
    jmp .outer

.found:
    mov rcx, 1
    jmp .exit

.not_found:
    mov rcx, r8
    mov rax, $asm_wstrlen
    call rax
    mov rbx, rax

    xor rcx, rcx

.exit:
    mov rax, rbx

    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 28h
    ret
)");

    //;remplacement de charactère par d'autres
    //;RCX = src
    //;RDX = string find
    //;R8 = string replace
    //;RAX = result: number of string find found
    g.text_add_function("asm_replace", R"(
    sub rsp, 38h
    mov [rsp+30h], rdx
    mov [rsp+28h], rcx
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rcx, rdx
    mov rax, $asm_strlen
    call rax
    mov rsi, rax
    test rax, rax
    jz .exit

    mov rdi, [rsp+28h]
    mov rax, 0
    mov [rsp+28h], rax

    mov rcx, r8
    mov rax, $asm_strlen
    call rax
    test rax, rax
    jz .not_string_r8

    mov rbx, r8

.string_r8:
    mov rcx, rdi
    mov rdx, [rsp+30h]
    mov rax, $asm_strstr
    call rax
    test rcx, rcx
    jz .exit

    mov rcx, rdi
    add rcx, rax
    mov rdi, rcx
    mov rdx, 0
    mov r8, rsi
    mov rax, $asm_strcut
    call rax

    mov rax, [rsp+28h]
    add rax, 1
    mov [rsp+28h], rax

    mov rcx, rdi
    mov rdx, rbx
    mov r8, 0
    mov rax, $asm_strcat
    call rax

    mov rcx, rbx
    mov rax, $asm_strlen
    call rax
    add rdi, rax
    jmp .string_r8

.not_string_r8:

    mov rcx, rdi
    mov rdx, [rsp+30h]
    mov rax, $asm_strstr
    call rax
    test rcx, rcx
    jz .exit

    mov rcx, rdi
    add rcx, rax
    mov rdx, 0
    mov r8, rsi
    mov rax, $asm_strcut
    call rax

    mov rax, [rsp+28h]
    add rax, 1
    mov [rsp+28h], rax

    jmp .not_string_r8

.exit:
    mov rax, [rsp+28h]

    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 38h
    ret

)");

    //;remplacement de charactère par d'autres
    //;RCX = src (UTF-16)
    //;RDX = string find (UTF-16)
    //;R8 = string replace (UTF-16)
    //;RAX = result: number of string find found
    g.text_add_function("asm_wreplace", R"(
    sub rsp, 38h
    mov [rsp+30h], rdx
    mov [rsp+28h], rcx
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rcx, rdx
    mov rax, $asm_wstrlen
    call rax
    mov rsi, rax
    test rax, rax
    jz .exit

    mov rdi, [rsp+28h]
    mov rax, 0
    mov [rsp+28h], rax

    mov rcx, r8
    mov rax, $asm_wstrlen
    call rax
    test rax, rax
    jz .not_string_r8

    mov rbx, r8

.string_r8:
    mov rcx, rdi
    mov rdx, [rsp+30h]
    mov rax, $asm_wstrstr
    call rax
    test rcx, rcx
    jz .exit

    mov rcx, rdi
    imul rax, 2
    add rcx, rax
    mov rdi, rcx
    mov rdx, 0
    mov r8, rsi
    mov rax, $asm_wstrcut
    call rax

    mov rax, [rsp+28h]
    add rax, 1
    mov [rsp+28h], rax

    mov rcx, rdi
    mov rdx, rbx
    mov r8, 0
    mov rax, $asm_wstrcat
    call rax

    mov rcx, rbx
    mov rax, $asm_wstrlen
    call rax
    imul rax, 2
    add rdi, rax
    jmp .string_r8

.not_string_r8:

    mov rcx, rdi
    mov rdx, [rsp+30h]
    mov rax, $asm_wstrstr
    call rax
    test rcx, rcx
    jz .exit

    mov rcx, rdi
    add rcx, rax
    mov rdx, 0
    mov r8, rsi
    mov rax, $asm_wstrcut
    call rax

    mov rax, [rsp+28h]
    add rax, 1
    mov [rsp+28h], rax

    jmp .not_string_r8

.exit:
    mov rax, [rsp+28h]

    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 38h
    ret

)");


    //; renvoie 0 ou 1 sur RAX si commence pareil / équal
    //; RCX = src
    //; RDX = string find
    //; R8  = taille de comparaison (toujours depuis le début du pointeur) (si 0 alors les deux chaînes doivent êtres identiques sur la taille de la chaîne rdx aumoins)
    g.text_add_function("asm_strcmp", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi

    xor eax, eax
    mov rsi, rcx
    mov rdi, rdx

    test r8, r8
    jz .full

.limited:
    mov al, [rsi]
    mov dl, [rdi]
    cmp al, dl
    jne .noteq
    test al, al
    jz .equal
    inc rsi
    inc rdi
    dec r8
    jnz .limited
    jmp .equal

.full:
    mov al, [rsi]
    mov dl, [rdi]
    cmp al, dl
    jne .noteq
    test al, al
    jz .equal
    inc rsi
    inc rdi
    jmp .full

.equal:
    mov eax, 1
    jmp .pile

.noteq:
    xor eax, eax

.pile:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    add rsp, 28h
    ret
)");

    //; renvoie 0 ou 1 sur RAX si commence pareil / équal
    //; RCX = src (UTF-16)
    //; RDX = string find (UTF-16)
    //; R8  = taille de comparaison (toujours depuis le début du pointeur) (si 0 alors les deux chaînes doivent êtres identiques sur la taille de la chaîne rdx aumoins)
    g.text_add_function("asm_wstrcmp", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi

    xor eax, eax
    mov rsi, rcx
    mov rdi, rdx

    test r8, r8
    jz .full

.limited:
    mov ax, [rsi]
    mov dx, [rdi]
    cmp ax, dx
    jne .noteq
    test ax, ax
    jz .equal
    add rsi, 2
    add rdi, 2
    dec r8
    jnz .limited
    jmp .equal

.full:
    mov ax, [rsi]
    mov dx, [rdi]
    cmp ax, dx
    jne .noteq
    test ax, ax
    jz .equal
    add rsi, 2
    add rdi, 2
    jmp .full

.equal:
    mov eax, 1
    jmp .pile

.noteq:
    xor eax, eax

.pile:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    add rsp, 28h
    ret
)");

    //; RCX = dest
    //; RDX = src
    //; R8  = position d'insertion (si plus grand que len de rcx finit au bout de la chaîne)
    g.text_add_function("asm_strcat", R"(
    sub rsp, 38h
    mov [rsp+30h], rdx
    mov [rsp+28h], rcx
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rdi, rcx
    mov rbx, rdx

    mov rcx, rdx
    mov rax, $asm_strlen
    call rax
    test rax, rax
    jz .done

    mov rcx, rdi
    mov rax, $asm_strlen
    call rax
    mov rsi, rax
    mov rdx, rbx
    cmp rsi, r8
    jae .ok_pos
    mov r8, rsi
.ok_pos:

    mov rbx, rsi

    mov rcx, rdx
    mov rsi, rdx
    mov rax, $asm_strlen
    call rax
    mov rdx, rsi
    mov rsi, rax

    add rdi, rbx
    add rdi, rsi
    dec rdi

    mov rcx, [rsp+28h]
    mov rsi, rcx
    add rsi, rbx
    dec rsi

    add rcx, r8

.shift_loop:
    cmp rsi, rcx
    jb .done_shift
    mov al, [rsi]
    mov [rdi], al
    dec rsi
    dec rdi
    jmp .shift_loop
.done_shift:

    mov rcx, [rsp+28h]
    mov rdi, rcx
    add rdi, r8
    mov rsi, rdx
    xor rcx, rcx

.copy_loop:
    mov al, [rsi+rcx]
    test al, al
    jz .done
    mov [rdi+rcx], al
    inc rcx
    jmp .copy_loop

.done:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 38h
    ret
)");

    //; RCX = dest (UTF-16)
    //; RDX = src  (UTF-16)
    //; R8  = position d'insertion (si plus grand que len de rcx finit au bout de la chaîne)
    g.text_add_function("asm_wstrcat", R"(
    sub rsp, 38h
    mov [rsp+30h], rdx
    mov [rsp+28h], rcx
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rdi, rcx
    mov rbx, rdx

    mov rcx, rdx
    mov rax, $asm_wstrlen
    call rax
    test rax, rax
    jz .done

    mov rcx, rdi
    mov rax, $asm_wstrlen
    call rax
    mov rsi, rax
    mov rdx, rbx
    cmp rsi, r8
    jae .ok_pos
    mov r8, rsi
.ok_pos:

    mov rbx, rsi

    mov rcx, rdx
    mov rsi, rdx
    mov rax, $asm_wstrlen
    call rax
    mov rdx, rsi
    mov rsi, rax

    imul rbx, 2
    imul rsi, 2

    add rdi, rbx
    add rdi, rsi
    sub rdi, 2

    mov rcx, [rsp+28h]
    mov rsi, rcx
    add rsi, rbx
    sub rsi, 2

    mov rax, r8
    imul rax, 2

    add rcx, rax

.shift_loop:
    cmp rsi, rcx
    jb .done_shift
    mov ax, [rsi]
    mov [rdi], ax
    sub rsi, 2
    sub rdi, 2
    jmp .shift_loop
.done_shift:

    mov rax, r8
    imul rax, 2

    mov rcx, [rsp+28h]
    mov rdi, rcx
    add rdi, rax
    mov rsi, rdx
    xor rcx, rcx

.copy_loop:
    mov ax, [rsi+rcx]
    test ax, ax
    jz .done
    mov [rdi+rcx], ax
    add rcx, 2
    jmp .copy_loop

.done:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 38h
    ret
)");

    //coupe la chaine rcx entre rdx et r8 (peut importe l'ordre de grandeur de r8 et rdx)
    //; RCX = char* str
    //; RDX = index1
    //; R8  = index2
    g.text_add_function("asm_strcut", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    cmp rdx, r8
    jbe .order_ok
    xchg rdx, r8
.order_ok:

    cmp rdx, r8
    je .done

    mov rdi, rcx
    mov rsi, rdx
    mov rax, $asm_strlen
    call rax
    mov rbx, rax

    mov rcx, rdi
    mov rdx, rsi

    mov rsi, 0

    cmp rdx, rbx
    jae .done

    cmp r8, rbx
    jbe .r8_ok
    mov r8, rbx
.r8_ok:

    lea rsi, [rcx + r8]
    lea rdi, [rcx + rdx]

.shift_loop:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .next_step
    inc rsi
    inc rdi
    jmp .shift_loop

.next_step:
    lea rsi, [rcx + rbx]

.zero_tail:
    cmp rdi, rsi
    jae .done
    mov byte ptr [rdi], 0
    inc rdi
    jmp .zero_tail

.done:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 28h
    ret
)");

    //coupe la chaine rcx entre rdx et r8 (peut importe l'ordre de grandeur de r8 et rdx)
    //; RCX = wchar_t* str (UTF-16)
    //; RDX = index1
    //; R8  = index2
    g.text_add_function("asm_wstrcut", R"(
    sub rsp, 28h
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    cmp rdx, r8
    jbe .order_ok
    xchg rdx, r8
.order_ok:

    cmp rdx, r8
    je .done

    mov rdi, rcx
    mov rsi, rdx
    mov rax, $asm_wstrlen
    call rax
    mov rbx, rax

    mov rcx, rdi
    mov rdx, rsi

    cmp rdx, rbx
    jae .done

    cmp r8, rbx
    jbe .r8_ok
    mov r8, rbx
.r8_ok:

    lea rsi, [rcx + r8*2]
    lea rdi, [rcx + rdx*2]

.shift_loop:
    mov ax, [rsi]
    mov [rdi], ax
    test ax, ax
    jz .next_step
    add rsi, 2
    add rdi, 2
    jmp .shift_loop

.next_step:
    lea rsi, [rcx + rbx*2]

.zero_tail:
    cmp rdi, rsi
    jae .done
    mov word ptr [rdi], 0
    add rdi, 2
    jmp .zero_tail

.done:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 28h
    ret
)");


    //; fonction fausse de asm_wstrcat mais conservé car fait de la copie mais dans une chaîne par pointeur r8 mais écrase (! disponible uniquement en utf16)
    //; RCX = dest (UTF-16)
    //; RDX = src  (UTF-16)
    //; R8  = position décrasement (si plus grand que len de rcx finit au bout de la chaîne sans écrasé)
    g.text_add_function("asm_wcopy_wstring", R"(
    sub rsp, 38h
    mov [rsp+30h], rdx
    mov [rsp+28h], rcx
    mov [rsp+20h], rsi
    mov [rsp+18h], rdi
    mov [rsp+10h], rbx

    mov rdi, rcx
    mov rbx, rdx
    mov rax, $asm_wstrlen
    call rax
    mov rsi, rax
    mov rdx, rbx
    cmp rsi, r8
    jae .ok_pos
    mov r8, rsi
.ok_pos:

    mov rbx, rsi

    mov rcx, rdx
    mov rsi, rdx
    mov rax, $asm_wstrlen
    call rax
    mov rdx, rsi
    mov rsi, rax

    shl rsi, 1
    shl rbx, 1
    shl rdx, 1

    add rdi, rbx
    add rdi, rsi
    sub rdi, 2

    mov rcx, [rsp+28h]
    mov rsi, rcx
    add rsi, rbx
    sub rsi, 2

    add rcx, r8
    shl rcx, 1

.shift_loop:
    cmp rsi, rcx
    jb .done_shift
    mov ax, [rsi]
    mov [rdi], ax
    sub rsi, 2
    sub rdi, 2
    jmp .shift_loop
.done_shift:

    mov rcx, [rsp+28h]
    mov rdi, rcx
    shl r8, 1
    add rdi, r8
    mov rsi, [rsp+30h]
    xor rcx, rcx

.copy_loop:
    mov ax, [rsi+rcx*2]
    test ax, ax
    jz .done
    mov [rdi+rcx*2], ax
    inc rcx
    jmp .copy_loop

.done:
    mov rsi, [rsp+20h]
    mov rdi, [rsp+18h]
    mov rbx, [rsp+10h]
    add rsp, 38h
    ret
)");

    // asm_ascii_utf16 : Convertit une chaîne ASCII (RCX) en UTF-16 (RDX)
    // Convertit une chaîne ASCII (RCX) en UTF-16 (RDX)
    //; RCX = adresse de la chaîne ASCII source
    //; RDX = adresse du tampon UTF-16 de destination
    //; R8 = longueur maximale (si 0, utilise asm_strlen)
    g.text_add_function("asm_ascii_utf16", R"(
    sub rsp, 28h
    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rdi, rdx
    mov rsi, rcx

    mov rax, $asm_strlen
    call rax
    test r8, r8
    jz the_strlen
    cmp r8, rax
    jbe skip_strlen
the_strlen:
    mov r8, rax
skip_strlen:

    mov rcx, r8

    add rsi, rcx
    mov rax, rcx
    imul rax, 2
    add rdi, rax
    add rdi, 2
    mov word ptr [rdi], 0
    inc rcx

reverse_loop_utf:
    cmp rcx, 0
    je ascii_done
    mov al,  byte ptr [rsi]
    dec rdi
    mov byte ptr [rdi], 0
    dec rdi
    mov byte ptr [rdi], al

    dec rsi
    dec rcx
    jmp reverse_loop_utf

ascii_done:
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = adresse de la chaîne UTF-16 source
    //; RDX = adresse du tampon ASCII de destination
    //; R8 = longueur maximale (si 0, utilise asm_wstrlen)
    // Convertit une chaîne UTF-16 (RCX) en ASCII (RDX)
    g.text_add_function("asm_utf16_ascii", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rdi, rdx

    mov rax, $asm_wstrlen
    call rax
    test r8, r8
    jz the_strlen
    cmp r8, rax
    jbe skip_strlen
the_strlen:
    mov r8, rax
skip_strlen:

    mov rsi, rcx
    xor rcx, rcx

utf16_to_ascii_loop:
    cmp rcx, r8
    jae utf16_done

    mov ax, word ptr [rsi+rcx*2]
    test ax, ax
    jz utf16_done

    mov byte ptr [rdi], al
    inc rdi

    inc rcx
    jmp utf16_to_ascii_loop

utf16_done:
    mov byte ptr [rdi], 0

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");


    // asm_addr_ascii : Convertit une adresse (RCX) en chaîne ASCII (16 octets) et écrit dans le buffer (RDX)
    //; RCX = adresse à convertir
    //; RDX = adresse du buffer (17 octets)
    //: R8 = copie de charactère (0=16 sinon R8)
    g.text_add_function("asm_addr_ascii", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rax, rcx
    test r8, r8
    jnz use_custom_len
    mov rcx, 16
    jmp len_ok

use_custom_len:
    mov rcx, r8

len_ok:
    mov rsi, rdx
    add rsi, rcx
    mov byte ptr [rsi], 0
    dec rsi

hex_loop:
    mov rbx, rax
    and rbx, 0xF
    cmp bl, 9
    jbe digit
    add bl, 'A' - 10
    jmp store
digit:
    add bl, '0'
store:
    mov byte ptr [rsi], bl
    dec rsi
    shr rax, 4
    dec rcx
    jnz hex_loop

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    // asm_addr_utf16 : Convertit une adresse (RCX) en chaîne UTF-16 (32 octets) et écrit dans le buffer (RDX)
    //; RCX = adresse à convertir
    //; RDX = adresse du buffer (34 octets car 00 finaux)
    //: R8 = copie de charactère (0=16 sinon R8)
    g.text_add_function("asm_addr_utf16", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rax, rcx
    test r8, r8
    jnz use_custom_len
    mov rcx, 16
    jmp len_ok

use_custom_len:
    mov rcx, r8

len_ok:
    mov rsi, rdx
    lea rsi, [rsi + rcx*2]
    mov word ptr [rsi], 0
    sub rsi, 2

hex_loop:
    mov rbx, rax
    and rbx, 0xF
    cmp bl, 9
    jbe digit
    add bl, 'A' - 10
    jmp store

digit:
    add bl, '0'

store:
    mov word ptr [rsi], bx
    sub rsi, 2
    shr rax, 4
    dec rcx
    jnz hex_loop

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = adresse valeur int à convertir
    //; RDX = adresse du buffer (17 octets)
    g.text_add_function("asm_addr_int_ascii", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rax, rcx
    mov rdi, rdx

    test rax, rax
    jns .positive
    mov byte ptr [rdi], '-'
    inc rdi
    neg rax
.positive:

    cmp rax, 0
    jne .convert
    mov byte ptr [rdi], '0'
    inc rdi
    mov byte ptr [rdi], 0
    ret

.convert:
    sub rsp, 32
    mov rsi, rsp
    xor rcx, rcx

.loop:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov byte ptr [rsi + rcx], dl
    inc rcx
    test rax, rax
    jnz .loop

.copy:
    dec rcx
    mov al, byte ptr [rsi + rcx]
    mov byte ptr [rdi], al
    inc rdi
    test rcx, rcx
    jnz .copy

    mov byte ptr [rdi], 0

    add rsp, 32

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = adresse valeur int à convertir
    //; RDX = adresse du buffer (32 octets)
    g.text_add_function("asm_addr_int_utf16", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rax, rcx
    mov rdi, rdx

    test rax, rax
    jns .positive
    mov word ptr [rdi], '-'
    add rdi, 2
    neg rax
.positive:

    cmp rax, 0
    jne .convert
    mov word ptr [rdi], '0'
    add rdi, 2
    mov word ptr [rdi], 0
    ret

.convert:
    sub rsp, 32
    mov rsi, rsp
    xor rcx, rcx

.loop:
    xor rdx, rdx
    mov rbx, 10
    div rbx
    add dl, '0'
    mov byte ptr [rsi + rcx], dl
    inc rcx
    test rax, rax
    jnz .loop

.copy:
    dec rcx
    mov al, byte ptr [rsi + rcx]
    mov word ptr [rdi], ax
    add rdi, 2
    test rcx, rcx
    jnz .copy

    mov word ptr [rdi], 0
    add rsp, 32

    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = char* source
    //; R8  = longueur max (0 = utiliser asm_strlen)
    //; RAX = résultat
    g.text_add_function("asm_addr_ascii_int", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    xor rax, rax
    xor rbx, rbx

    mov rsi, rcx

    test r8, r8
    jnz have_len
    mov rax, $asm_strlen
    call rax
    mov r8, rax
have_len:

    xor rcx, rcx
    xor rax, rax

.skip_spaces:
    cmp rcx, r8
    jae .done
    mov dl, byte ptr [rsi + rcx]
    cmp dl, ' '
    jne .check_sign
    inc rcx
    jmp .skip_spaces

.check_sign:
    cmp dl, '-'
    jne .check_plus
    mov bl, 1
    inc rcx
    jmp .parse

.check_plus:
    cmp dl, '+'
    jne .parse
    inc rcx

.parse:
    cmp rcx, r8
    jae .done

    mov dl, byte ptr [rsi + rcx]
    cmp dl, '0'
    jb .done
    cmp dl, '9'
    ja .done

    imul rax, rax, 10
    sub dl, '0'
    movzx rdx, dl
    add rax, rdx

    inc rcx
    jmp .parse

.done:
    test bl, bl
    jz .ret
    neg rax
.ret:
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = wchar_t* source
    //; R8  = longueur max (0 = utiliser asm_wstrlen)
    //; RAX = résultat
    g.text_add_function("asm_addr_utf16_int", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    xor rax, rax
    xor rbx, rbx

    mov rsi, rcx

    test r8, r8
    jnz have_len
    mov rax, $asm_wstrlen
    call rax
    mov r8, rax
have_len:

    xor rcx, rcx
    xor rax, rax

.skip_spaces:
    cmp rcx, r8
    jae .done
    mov dx, word ptr [rsi + rcx*2]
    cmp dx, ' '
    jne .check_sign
    inc rcx
    jmp .skip_spaces

.check_sign:
    cmp dx, '-'
    jne .check_plus
    mov bl, 1
    inc rcx
    jmp .parse

.check_plus:
    cmp dx, '+'
    jne .parse
    inc rcx

.parse:
    cmp rcx, r8
    jae .done

    mov dx, word ptr [rsi + rcx*2]
    cmp dx, '0'
    jb .done
    cmp dx, '9'
    ja .done

    imul rax, rax, 10
    sub dx, '0'
    movzx rdx, dx
    add rax, rdx

    inc rcx
    jmp .parse

.done:
    test bl, bl
    jz .ret
    neg rax
.ret:
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; XMM0 = double
    //; RDX = buffer
    //; R8 = num after comma (-1 pour prendre la valeur par défaut, sinon n'affiche pas de virgule)
    g.text_add_function("asm_addr_double_ascii", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    cmp r8, -1
    jne .skip_default_digits
    mov r8, 6
.skip_default_digits:
    sub rsp, 16
    mov [rsp], r8

    sub rsp, 16
    movdqu [rsp], xmm0


    mov rdi, rdx

    movq rax, xmm0
    mov rbx, 0x8000000000000000
    test rax, rbx
    jz .positive

    mov byte ptr [rdi], '-'
    inc rdi
    mov rbx, 0x7FFFFFFFFFFFFFFF
    and rax, rbx
    movq xmm0, rax

.positive:
    cvttsd2si rax, xmm0
    mov r8, rax

    mov rcx, rax
    mov rdx, rdi
    mov rax, $asm_addr_int_ascii
    call rax

    movdqu xmm0, [rsp]
    add rsp, 16

.find_end:
    cmp byte ptr [rdi], 0
    je .after_int
    inc rdi
    jmp .find_end

.after_int:
    mov rcx, [rsp]
    add rsp, 16

    cmp rcx, 0
    je .no_round

    mov byte ptr [rdi], '.'
    inc rdi

    movq rax, xmm0
    mov rbx, 0x8000000000000000
    test rax, rbx
    jz .frac_positive
    mov rbx, 0x7FFFFFFFFFFFFFFF
    movq rax, xmm0
    and rax, rbx
    movq xmm0, rax

.frac_positive:
    cvtsi2sd xmm1, r8
    subsd xmm0, xmm1

.frac_loop:
    mov rbx, 0x4024000000000000
    movq xmm2, rbx
    mulsd xmm0, xmm2

    cvttsd2si rax, xmm0
    and rax, 0xF
    add al, '0'
    mov byte ptr [rdi], al
    inc rdi

    sub al, '0'
    cvtsi2sd xmm1, rax
    subsd xmm0, xmm1

    dec rcx
    jnz .frac_loop

    movq rax, xmm0
    mov rbx, 0x4024000000000000
    movq xmm1, rbx
    mulsd xmm0, xmm1
    cvttsd2si rax, xmm0
    cmp rax, 5
    jb .no_round

dec rdi
.round_loop:
    mov al, byte ptr [rdi]
    inc al
    cmp al, '9'+1
    jne .done_round
    mov byte ptr [rdi], '0'
    dec rdi
    inc rcx
    jmp .round_loop

.done_round:
    mov byte ptr [rdi], al
    inc rcx

.no_round:
    mov byte ptr [rdi+rcx], 0
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    //; RCX = char*
    //; RAX = double (dans xmm0)
    g.text_add_function("asm_addr_ascii_double", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rsi, rcx
    xor rbx, rbx
    xor rax, rax

.skip_spaces:
    mov dl, byte ptr [rsi]
    cmp dl, ' '
    jne .check_sign
    inc rsi
    jmp .skip_spaces

.check_sign:
    cmp dl, '-'
    jne .check_plus
    mov bl, 1
    inc rsi
    jmp .read_int

.check_plus:
    cmp dl, '+'
    jne .read_int
    inc rsi

.read_int:
    xor rax, rax

.int_loop:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .after_int
    cmp dl, '9'
    ja .after_int
    imul rax, rax, 10
    sub dl, '0'
    movzx rdx, dl
    add rax, rdx
    inc rsi
    jmp .int_loop

.after_int:
    cvtsi2sd xmm0, rax

    mov dl, byte ptr [rsi]
    cmp dl, '.'
    jne .apply_sign
    inc rsi

    mov rcx, 0

.count_frac:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .frac_done_count
    cmp dl, '9'
    ja .frac_done_count
    inc rcx
    inc rsi
    jmp .count_frac

.frac_done_count:
    test rcx, rcx
    jz .apply_sign

    dec rsi

    pxor xmm1, xmm1
    mov r8, 0x3FB999999999999A

.frac_loop:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .done_frac
    cmp dl, '9'
    ja .done_frac

    sub dl, '0'
    movzx rax, dl
    cvtsi2sd xmm2, rax

    movq xmm3, r8
    addsd xmm1, xmm2

    mulsd xmm1, xmm3

    divsd xmm2, xmm3

    dec rsi
    jmp .frac_loop

.done_frac:
    addsd xmm0, xmm1

.apply_sign:
    test bl, bl
    jz .done
    movq rax, xmm0
    mov rbx, 0x8000000000000000
    xor rax, rbx
    movq xmm0, rax

.done:
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    g.text_add_function("asm_addr_float_ascii", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    cmp r8, -1
    jne .skip_default_digits
    mov r8, 6
.skip_default_digits:
    sub rsp, 16
    mov [rsp], r8

    sub rsp, 16
    movdqu [rsp], xmm0

    mov rdi, rdx

    movq rax, xmm0
    mov rbx, 0x80000000
    test rax, rbx
    jz .positive

    mov byte ptr [rdi], '-'
    inc rdi
    mov rbx, 0x7FFFFFFF
    and rax, rbx
    movq xmm0, rax

.positive:
    cvttss2si rax, xmm0
    mov r8, rax

    mov rcx, rax
    mov rdx, rdi
    mov rax, $asm_addr_int_ascii
    call rax

    movdqu xmm0, [rsp]
    add rsp, 16

.find_end:
    cmp byte ptr [rdi], 0
    je .after_int
    inc rdi
    jmp .find_end

.after_int:
    mov rcx, [rsp]
    add rsp, 16

    cmp rcx, 0
    je .no_round

    mov byte ptr [rdi], '.'
    inc rdi

    movq rax, xmm0
    mov rbx, 0x80000000
    test rax, rbx
    jz .frac_positive
    mov rbx, 0x7FFFFFFF
    movq rax, xmm0
    and rax, rbx
    movq xmm0, rax

.frac_positive:
    cvtsi2ss xmm1, r8
    subss xmm0, xmm1

.frac_loop:
    mov rbx, 0x41C00000
    movd xmm2, ebx
    mulss xmm0, xmm2

    cvttss2si rax, xmm0
    and rax, 0xF
    add al, '0'
    mov byte ptr [rdi], al
    inc rdi

    sub al, '0'
    cvtsi2ss xmm1, rax
    subss xmm0, xmm1

    dec rcx
    jnz .frac_loop

    movq rax, xmm0
    mov rbx, 0x41C00000
    movd xmm1, ebx
    mulss xmm0, xmm1
    cvttss2si rax, xmm0
    cmp rax, 5
    jb .no_round

    dec rdi
.round_loop:
    mov al, byte ptr [rdi]
    inc al
    cmp al, '9'+1
    jne .done_round
    mov byte ptr [rdi], '0'
    dec rdi
    inc rcx
    jmp .round_loop

.done_round:
    mov byte ptr [rdi], al
    inc rcx

.no_round:
    mov byte ptr [rdi+rcx], 0
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

    g.text_add_function("asm_addr_ascii_float", R"(
    sub rsp, 28h

    mov [rsp+20h], rbx
    mov [rsp+18h], rsi
    mov [rsp+10h], rdi

    mov rsi, rcx
    xor rbx, rbx
    xor rax, rax

.skip_spaces:
    mov dl, byte ptr [rsi]
    cmp dl, ' '
    jne .check_sign
    inc rsi
    jmp .skip_spaces

.check_sign:
    cmp dl, '-'
    jne .check_plus
    mov bl, 1
    inc rsi
    jmp .read_int

.check_plus:
    cmp dl, '+'
    jne .read_int
    inc rsi

.read_int:
    xor rax, rax

.int_loop:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .after_int
    cmp dl, '9'
    ja .after_int
    imul rax, rax, 10
    sub dl, '0'
    movzx rdx, dl
    add rax, rdx
    inc rsi
    jmp .int_loop

.after_int:
    cvtsi2ss xmm0, rax

    mov dl, byte ptr [rsi]
    cmp dl, '.'
    jne .apply_sign
    inc rsi

    mov rcx, 0

.count_frac:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .frac_done_count
    cmp dl, '9'
    ja .frac_done_count
    inc rcx
    inc rsi
    jmp .count_frac

.frac_done_count:
    test rcx, rcx
    jz .apply_sign

    dec rsi

    pxor xmm1, xmm1
    mov r8d, 0x3E4CCCCD

.frac_loop:
    mov dl, byte ptr [rsi]
    cmp dl, '0'
    jb .done_frac
    cmp dl, '9'
    ja .done_frac

    sub dl, '0'
    movzx rax, dl
    cvtsi2ss xmm2, rax

    movd xmm3, r8d
    addss xmm1, xmm2

    mulss xmm1, xmm3
    divss xmm2, xmm3

    dec rsi
    jmp .frac_loop

.done_frac:
    addss xmm0, xmm1

.apply_sign:
    test bl, bl
    jz .done
    mov eax, 0x80000000
    movd xmm1, eax
    xorps xmm0, xmm1
.done:
    mov rbx, [rsp+20h]
    mov rsi, [rsp+18h]
    mov rdi, [rsp+10h]

    add rsp, 28h
    ret
)");

}
