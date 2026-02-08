ASM64CPP
; asm_cpp64 test2.asm bob.exe --cmd
include default:

global hello:   ;changer cette ligne pour changer la fonction à exécuter en premier

section .rsrc

icon "frx.ico" ; chemin de l'ico
version_simple "1.0.0.0" "MonApp.exe" "2026 \" Moi !"       ; version | nom de exe | copyright
manifest_simple "bob.exe" "1.0.0.0" false false false true   ; nom de exe | version | dpiAware | perMonitorV2 | requireAdmin | commonV6

; manifest_xml "contenu"  ; fait le manifest complet
; version_full fileVersion | productVersion | companyName | fileDescription | productName | originalFilename | copyright

section .data

;pour les hello et bob
ascii msg "-6532.8736841452"
ascii msg2 "6532"
ascii msg3 "2"
buffer tmpbuf 256
little msg_encode 0x40B986DFA43FE5C9  ; exemple de valeur double 6534.8736 (pour écrire de l'hexadécimale en big remplacer little par big, pour écrire en entier la valeur en hexa, enlevé 0x et écrire un nombre entier ici 4663907184210339273 est équivalent)

;pour bob2
buffer result_buf 200
utf16 msg_c "hello la  !\n"
utf16 msg_v "vache"
; attention, little et big ne complete pas les 8 octets minimum d'une adresse si on en fournit moins, il faut en écrire autant que l'on veux même les 0.

;pour bob3
ascii chaine "bonjour !\n"
buffer buf 10   ; espace de sécurité pour la modification de chaine
ascii remplacement "aurevoir"
ascii recherche "bonjour"

section .idata

kernel32.dll ExitProcess
msvcrt.dll printf wprintf puts

section .text

;fonction de sortie
proc exit
    sub rsp, 30h
    xor ecx, ecx
    mov rax, $ExitProcess
    mov rax, [rax]
    call rax
    add rsp, 30h
    ret
end exit

proc hello
    ; script de calcul de double
    ;ne pas utiliser xmm0 xmm1 xmm2 et xmm3 utiliser pour les calculs interne (xmm0 = reponse pour asm_addr_ascii_double et entrée pour asm_addr_double_ascii)
    ;test de double existant
    ;mov rax, 0x40B986DFA43FE5C9 ; 6534.8736
    ;mov rax, 0xC0B986DFA43FE5C9 ; negatif de 6534.8736
    ;mov rax, 0x40B98F6F3FD3C1C6 ; autre
    ;movq xmm0, rax
    sub rsp, 28h

    mov rcx, $msg
    xor r8, r8
    mov rax, $asm_addr_ascii_double
    call rax

    movsd xmm15, xmm0 ; sauvgarder le premier nombre pour calcul

    mov rcx, $msg2
    xor r8, r8
    mov rax, $asm_addr_ascii_double
    call rax

    movsd xmm14, xmm0 ; sauvgarder le deuxième nombre pour calcul

    mov rcx, $msg3
    xor r8, r8
    mov rax, $asm_addr_ascii_double
    call rax

    addsd xmm14, xmm15 ; sum
    subsd xmm15, xmm14 ; retirer la virgule stocker sur xmm15
    divsd xmm15, xmm0  ; diviser par msg3

    movsd xmm0, xmm15  ;copie du nombre de retour

    mov rax, 0x7FFFFFFFFFFFFFFF  ;convertion en positif
    movq xmm1, rax
    andpd xmm0, xmm1

    ; test avec le tampon écrit en hexa directement en little endian
    ;mov rax, $msg_encode
    ;mov rax, [rax]
    ;movq xmm0, rax

    mov rdx, $tmpbuf
    mov r8, 10
    mov rax, $asm_addr_double_ascii
    call rax

    ; wprintf(tmpbuf)
    mov rcx, $tmpbuf
    mov rax, $printf
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end hello

proc hello2
    ; script de calcul de float (double en 32bits)
    ;ne pas utiliser xmm0 xmm1 xmm2 et xmm3 utiliser pour les calculs interne (xmm0 = reponse pour asm_addr_ascii_float et entrée pour asm_addr_float_ascii)
    sub rsp, 28h

    mov rcx, $msg
    xor r8, r8
    mov rax, $asm_addr_ascii_float
    call rax

    movss xmm15, xmm0 ; sauvgarder le premier nombre pour calcul

    mov rcx, $msg2
    xor r8, r8
    mov rax, $asm_addr_ascii_float
    call rax

    movss xmm14, xmm0 ; sauvgarder le deuxième nombre pour calcul

    mov rcx, $msg3
    xor r8, r8
    mov rax, $asm_addr_ascii_float
    call rax

    addss xmm14, xmm15 ; sum
    subss xmm15, xmm14 ; retirer la virgule stocker sur xmm15
    divss xmm15, xmm0  ; diviser par msg3

    movss xmm0, xmm15  ;copie du nombre de retour

    mov rax, 0x7FFFFFFF  ;convertion en positif
    movd xmm1, eax
    andps xmm0, xmm1

    mov rdx, $tmpbuf
    mov r8, 10
    mov rax, $asm_addr_float_ascii
    call rax

    ; wprintf(tmpbuf)
    mov rcx, $tmpbuf
    mov rax, $printf
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end hello2

;modification de chaine
proc bob
    sub rsp, 28h
    mov rcx, $msg2
    mov r8, 0
    mov rax, $asm_addr_ascii_int
    call rax

    mov rcx, rax
    mov rdx, $tmpbuf
    mov r8, 0
    mov rax, $asm_addr_int_utf16
    call rax

    mov rcx, $tmpbuf
    add rcx, 100        ; décalage pour ne pas copier tout les charactères
    mov rdx, $tmpbuf
    add rdx, 100      ;+ 100 pour marge car tampon de 256
    mov r8, 3         ; copy les charactères

    mov rsi, rdx      ; copi sur rsi pour après

    mov rax, $asm_wcopy
    call rax

    ;affiche la longueur en hexa de la copie
    mov rcx, $tmpbuf
    add rcx, 100
    mov rax, $asm_wstrlen
    call rax
    mov rcx, rax
    mov rdx, $tmpbuf
    add rdx, 200
    mov r8, 0
    mov rax, $asm_addr_ascii
    call rax
    mov rcx, $tmpbuf
    add rcx, 200
    mov rax, $puts
    mov rax, [rax]
    call rax
    ;fin affiche

    mov rcx, $tmpbuf
    mov rdx, rsi
    mov r8, 0
    mov rax, $asm_wstrstr
    call rax

    mov rsi, rcx  ; result trouver ou non

    mov rcx, rax  ; result position a écrire
    mov rdx, $result_buf
    mov r8, 0
    mov rax, $asm_addr_utf16
    call rax

    mov rcx, rsi ; result trouver a écrire
    mov rdx, $result_buf
    add rdx, 34
    mov r8, 0
    mov rax, $asm_addr_utf16
    call rax

    ; /n en utf-16 entre les deux addresses
    mov rdx, $result_buf
    add rdx, 32
    mov ax, 0x000A
    mov [rdx], ax

    mov rcx, $result_buf

    mov rax, $wprintf
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end bob

;modification de chaine
proc bob2
    sub rsp, 28h

    mov rcx, $msg_c
    mov rdx, $result_buf
    xor r8, r8
    mov rax, $asm_wcopy
    call rax

    mov rcx, $result_buf
    mov rdx, $msg_v
    mov r8, 9
    mov rax, $asm_wstrcat
    call rax

    mov rcx, $result_buf
    mov rax, $wprintf
    mov rax, [rax]
    call rax

    mov rcx, $result_buf
    add rcx, 0
    mov rax, $asm_wstrlen
    call rax

    mov rcx, $result_buf
    mov rdx, 5
    mov r8, 8
    mov rax, $asm_wstrcut
    call rax

    mov rcx, $result_buf
    mov rax, $wprintf
    mov rax, [rax]
    call rax

    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end bob2

;remplacement de chaine
proc bob3
    sub rsp, 28h
    mov rcx, $chaine
    mov rax, $printf
    mov rax, [rax]
    call rax

    mov rcx, $chaine
    mov rdx, $recherche
    mov r8, $remplacement
    mov rax, $asm_replace
    call rax

    mov rcx, $chaine
    mov rax, $printf
    mov rax, [rax]
    call rax
    add rsp, 28h

    mov rax, $exit
    call rax
    ret
end bob3
