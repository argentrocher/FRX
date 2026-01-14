ASM64CPP
//blob

global hello :                        ; deglaration du nom du point d'entrer fichier (de base main )

section .rsrc
icon "frx.ico"                                                                       ; chemin de l'ico
version_simple "1.0.0.0" "MonApp.exe" "2026 \" Moi !"       ; version | nom de exe | copyright
manifest_simple "bob.exe" "1.0.0.0" false false false true   ; nom de exe | version | dpiAware | perMonitorV2 | requireAdmin | commonV6

; manifest_xml "contenu"  ; fait le manifest complet
; version_full fileVersion | productVersion | companyName | fileDescription | productName | originalFilename | copyright

dialog 4 "Test DialogBoxParamW" 100 100 180 80 "MS Shell Dlg" 1 12 false
control 4 DRAWRECT 1000 "" 0 0 180 80
control 4 EDIT 1003 "..." 20 35 140 12
control 4 DEFBUTTON 1001 "OK" 20 55 40 16
control 4 BUTTON 1002 "Cancel" 120 55 40 16
control 4 DRAWRECT 1004 "" 148 2 30 30

section .data

ascii msg1 "Cancel !\n"
ascii msg2 "Closed !\n"
ascii done_msg "FINI !\n"
ascii msg "NONE\n"
utf16 msg_label "Choisissez une option :"
utf16 msg_prefix "entre ton texte ..."
buffer entry_buf_w 512
buffer entry_buf_a 256
buffer buf_adr 16

section .idata

msvcrt.dll printf puts
kernel32.dll CreateThread WaitForSingleObject GetModuleHandleW ExitProcess lstrlenW
user32.dll DialogBoxParamW EndDialog GetDlgItemTextW SendDlgItemMessageW
gdi32.dll CreateSolidBrush GetStockObject Ellipse Rectangle TextOutW SetTextColor SetBkMode SelectObject DeleteObject


section .text

proc dialog
    push rbx
    push rsi
    push rdi
    dialog_proc:
    cmp edx, 0x110          ; WM_INITDIALOG
    je .init
    cmp edx, 0x111          ; WM_COMMAND
    je .command
    cmp edx, 0x2B           ; WM_DRAWITEM
    je .draw_item           ;fait le cercle et la couleur du fond
    .draw_exit:             ;normal si pas d'arg ou fin du draw
    xor eax, eax
    jmp .exit

    .init:

    ; peut être enlevé pour conservé le texte fournit au départ dans rt_dialog pour edit
    mov rdi, rcx             ; hwnd de la dialog sauvgarde sur rdi

    ; vider l'edit avant pour afficher le texte en arrière plan de edit proprement
    sub rsp, 28h

    mov rdx, 1003
    mov r8d, 000Ch          ; WM_SETTEXT
    xor r9d, r9d            ; NULL
    mov qword ptr [rsp+20h], 0

    mov rax, $SendDlgItemMessageW
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rcx, rdi             ; restore le hwnd de la dialog sauvgardé sur rdi
    ; fin peut être enlevé

    ; --- EM_SETCUEBANNER pour EDIT 1003 ---
    sub rsp, 28h                 ; shadow space + align

    mov rdx, 1003                ; ID de l'EDIT
    mov r8d, 1501h               ; EM_SETCUEBANNER
    mov r9d, 1                  ; TRUE (disparaît dès focus)

    mov rax, $msg_prefix          ; wchar_t* du placeholder (texte de l'EDIT en arrière plan)
    mov [rsp+20h], rax              ; LPARAM sur la stack

    mov rax, $SendDlgItemMessageW
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov eax, 1
    jmp .exit

    .command:

    movzx eax, r8w           ; id du bouton cliqué
    mov rcx, rcx            ; hwnd
    xor edx, edx
    mov dx, ax              ; id du bouton pour enddialog
    cmp eax, 1001            ; OK id
    je .ok
    cmp eax, 1002            ; Cancel id
    je .cancel
    cmp eax, 2               ; fermeture croix ou ESC id
    je .closed
    jmp .exit                   ; rien exit


    .ok:
    sub rsp, 28h
    ;on récupère le texte du contrôle EDIT id=1003
    mov rdi, rcx                    ; hwnd de la dialog sauvgarde sur rdi
    mov edx, 1003               ; id du contrôle EDIT
    mov r8, $entry_buf_w    ; buffer wchar_t VA fourni pour stocker le texte (taille 512 car en char mais donner 256)
    mov r9d, 256                 ; taille max du buffer
    mov rax, $GetDlgItemTextW  ; GetDlgItemTextW
    mov rax, [rax]
    call rax
    add rsp, 28h

    mov rcx, rdi            ; hwnd restoration depuis rdi
    xor edx, edx

    jmp .convertion_func        ; aller au code de conversion
    .return_convertion_func:  ; retour du code de conversion

    mov rax, $entry_buf_a
    mov rdx, $buf_adr
    mov [rdx], rax            ; écrire dans le buffer prédéfinit l'adresse du texte à lire (donc le texte en ascii)
    jmp .end_command

    .cancel:
    mov rax, $msg1
    mov rdx, $buf_adr
    mov [rdx], rax           ; écrire dans le buffer prédéfinit l'adresse du texte à lire
    jmp .end_command

    .closed:
    mov rax, $msg2
    mov rdx, $buf_adr
    mov [rdx], rax        ; écrire dans le buffer prédéfinit l'adresse du texte à lire
    jmp .end_command

    .end_command:
    mov eax, 1         ; dire à DialogBoxParam que WM_COMMAND est traité
    sub rsp, 28h
    mov rbx, rax
    mov rax, $EndDialog
    mov rax, [rax]
    call rax

    add rsp, 28h

    jmp .exit


    .draw_item:
    cmp r8, 1004        ; vérifie que c'est notre DRAWRECT (faire un cercle blue dedans)
    je .draw_circle
    cmp r8, 1000
    je .draw_background
    jmp .draw_exit

    .draw_background:
    mov rax, r9                ; rax = LPDRAWITEMSTRUCT*
    mov rbx, [rax+0x20]   ; rbx = HDC

    ;  RECT = [rax+0x10]
    mov rax, r9
    mov eax, [rax+0x28]
    mov r12, rax       ; left
    mov rax, r9
    mov eax, [rax+0x2C]
    mov r13, rax       ; top
    mov rax, r9
    mov eax, [rax+0x30]
    mov r14, rax       ; right
    mov rax, r9
    mov eax, [rax+0x34]
    mov r15, rax       ; bottom

    sub rsp, 28h
    ; créer un hbrush orange RGB(255,160,5)
    mov ecx, 0x05A0FF         ; COLORREF = BGR(,,)
    mov rax, $CreateSolidBrush
    mov rax, [rax]
    call rax
    mov rsi, rax      ; sauvegarde HBRUSH
    add rsp, 28h

    ; selectionne le HBRUSH creer
    sub rsp, 28h
    mov rcx, rbx       ; HDC
    mov rdx, rsi        ; HBRUSH creer
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    mov rdi, rax        ; sauvegarde ancien brush
    add rsp, 28h

    ; creer un null_pen
    sub rsp, 28h
    mov ecx, 8                ; NULL_PEN = 8 dans GetStockObject
    mov rax, $GetStockObject
    mov rax, [rax]
    call rax
    mov r11, rax             ; sauvegarde le stylo nul
    add rsp, 28h

    ; selectionne le null_pen creer
    sub rsp, 28h
    mov rcx, rbx        ; HDC
    mov rdx, r11        ; null_pen creer
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    mov r10, rax        ; sauvegarde ancien stylo
    add rsp, 28h

    sub rsp, 28h
    ; Dessine le rectangle (fond)
    mov rcx, rbx     ; HDC
    mov rdx, r12     ; left
    mov r8, r13      ; top
    mov r9, r14      ; right
    mov qword ptr [rsp+20h], r15 ; bottom sur stack
    mov rax, $Rectangle
    mov rax, [rax]
    call rax
    add rsp, 28h


    ; selectionne le pen d'origine
    sub rsp, 28h
    mov rcx, rbx        ; HDC
    mov rdx, r10        ; retstorer l'ancien stylo
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    add rsp, 28h

    ;  selectionne le HBRUSH d'origine
    sub rsp, 28h
    mov rcx, rbx        ; HDC
    mov rdx, rdi        ; retstorer l'ancien brush
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    add rsp, 28h

    sub rsp, 28h
    ; nettoyer le HBRUSH creer stocker sur rsi
    mov rcx, rsi
    mov rax, $DeleteObject
    mov rax, [rax]
    call rax
    add rsp, 28h

    ; selectionne la couleur du texte
    sub rsp, 28h
    mov rcx, rbx                    ; HDC
    mov edx, 0x000000        ; noir
    mov rax, $SetTextColor
    mov rax, [rax]
    call rax
    add rsp, 28h

    ; fond transparent
    sub rsp, 28h
    mov rcx, rbx             ; HDC
    mov edx, 1               ; TRANSPARENT
    mov rax, $SetBkMode
    mov rax, [rax]
    call rax
    add rsp, 28h

    ; calculer la longueur exacte de la chaîne pour afficher le texte avec lstrlenW
    sub rsp, 28h
    mov rcx, $msg_label
    mov rax, $lstrlenW
    mov rax, [rax]
    call rax
    add rsp, 28h
    ; reponse dans rax, pas besoin de le bouger vu que appeller après

    ; texte du label mais avec le font correct pas comme si on le met dans rt_dialog LABEL (même position)
    sub rsp, 28h
    mov rcx, rbx                ; HDC
    mov rdx, 0x30              ; x
    mov r8, 0x35                   ; y
    mov r9, $msg_label      ; texte UTF-16
    mov qword ptr [rsp+20h], rax  ; c  (longueur exacte de la chaine)
    mov rax, $TextOutW
    mov rax, [rax]
    call rax
    add rsp, 28h

    jmp .draw_exit


    .draw_circle:
    mov rax, r9               ; rax = LPDRAWITEMSTRUCT*
    mov rbx, [rax+0x20]  ; rbx = HDC

    ; RECT = [rax+0x10]
    mov rax, r9
    mov eax, [rax+0x28]
    mov r12, rax       ; left
    mov rax, r9
    mov eax, [rax+0x2C]
    mov r13, rax       ; top
    mov rax, r9
    mov eax, [rax+0x30]
    mov r14, rax       ; right
    mov rax, r9
    mov eax, [rax+0x34]
    mov r15, rax       ; bottom

    sub rsp, 28h
    ; créer un brush bleu RGB(0,0,255)
    mov ecx, 0xFF0000         ; COLORREF = BGR(,,)
    mov rax, $CreateSolidBrush
    mov rax, [rax]
    call rax
    mov rsi, rax      ;  sauvegarde HBRUSH
    add rsp, 28h

    ; selectionne le HBRUSH creer
    sub rsp, 28h
    mov rcx, rbx       ; HDC
    mov rdx, rsi        ; HBRUSH creer (bleu)
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    mov rdi, rax        ; sauvegarde ancien brush
    add rsp, 28h

    sub rsp, 28h
    ; Dessine le cercle
    mov rcx, rbx      ; HDC
    mov rdx, r12      ; left
    mov r8, r13       ; top
    mov r9, r14       ; right
    mov qword ptr [rsp+20h], r15 ; bottom sur stack
    mov rax, $Ellipse
    mov rax, [rax]
    call rax
    add rsp, 28h

    ; selectionne le HBRUSH d'origine
    sub rsp, 28h
    mov rcx, rbx       ; HDC
    mov rdx, rdi        ; retstorer l'ancien brush
    mov rax, $SelectObject
    mov rax, [rax]
    call rax
    add rsp, 28h

    sub rsp, 28h
    ; nettoyer le HBRUSH creer stocker sur rsi
    mov rcx, rsi
    mov rax, $DeleteObject
    mov rax, [rax]
    call rax
    add rsp, 28h

    jmp .draw_exit

    .exit:
    pop rdi
    pop rsi
    pop rbx
    ret


    ; convertion utf-16 en ascii
    .convertion_func:
    mov rsi, $entry_buf_w            ; source UTF-16
    mov rdi, $entry_buf_a      ; destination ASCII

    .convert_utf16_to_ascii:
    mov ax, word ptr [rsi]       ; lire wchar_t
    test ax, ax
    je .done_convert             ; fin si 0

    cmp ax, 0x007F
    ja .non_ascii

    mov byte ptr [rdi], al       ; ASCII direct
    jmp .next_char

    .non_ascii:
    mov byte ptr [rdi], '?'      ; remplacement

    .next_char:
    add rsi, 2                  ; wchar_t++
    inc rdi                     ; char++
    jmp .convert_utf16_to_ascii

    .done_convert:
    mov byte ptr [rdi], 0        ; null-terminate ASCII
    xor rsi, rsi
    xor rdi, rdi
    mov rdi, 1
    jmp .return_convertion_func
end dialog

proc hello
        ; prologue for main - reserve shadow + extra stack space
        sub rsp, 28h

        ; hInstance = GetModuleHandleW(NULL)
        xor rcx, rcx
        mov rax, $GetModuleHandleW
        mov rax, [rax]
        call rax

        ; After wait, free stack reserved earlier
        add rsp, 28h
        sub rsp, 28h

        ; DialogBoxParamW(hInst, ID=1, NULL, dialog_proc, 0)
        mov rcx, rax                         ; hInstance
        mov rdx, 4                            ; MAKEINTRESOURCEW(4)   (on a donné comme id 4 la rt_dialog)
        xor r8, r8                              ; parent = NULL
        mov r9, $dialog   ; nom du script de la fenêtre (addr)

        mov qword ptr [rsp+20h], 0

        mov rax, $DialogBoxParamW
        mov rax, [rax]
        call rax
        mov rbx, $buf_adr   ; récupère l'adresse de la réponse dialog dans le buffer

        ; After wait, free stack reserved earlier
        add rsp, 28h
        sub rsp, 28h

        ; Print final message: puts("FINI !\n")
        mov rcx, $done_msg
        mov rax, $puts
        mov rax, [rax]
        call rax

        ; After wait, free stack reserved earlier
        add rsp, 28h
        sub rsp, 28h

        ; appeler puts (affiche message) keystone ne comprend pas donc ignore et cut en 2 main alors que c'est la suite
        mov rax, [rbx]  ; reprend la réponse (adresse de rbx)
        mov rcx, rax
        mov rax, $puts
        mov rax, [rax]
        call rax

        ; After wait, free stack reserved earlier
        add rsp, 28h
        sub rsp, 28h

        ; ExitProcess(0)
        xor ecx, ecx
        mov rax, $ExitProcess
        mov rax, [rax]
        call rax
        ret      ;   terminer
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

