#include "pe_gen_window64.hpp"

//g++ -std=c++17 test_lib_window64_2.cpp -lkeystone -o test_lib_window64_2.exe

int main() {
    GESTION g;

    // ===============================
    // . Imports
    // ===============================
    g.idata_add_imports({
        { "msvcrt.dll", { "printf", "puts" } },
        { "kernel32.dll", { "CreateThread", "WaitForSingleObject", "GetModuleHandleW", "ExitProcess", "lstrlenW" } },
        { "user32.dll", {"DialogBoxParamW", "EndDialog", "GetDlgItemTextW", "SendDlgItemMessageW"} },
        { "gdi32.dll", {"CreateSolidBrush", "GetStockObject", "Ellipse", "Rectangle", "TextOutW", "SetTextColor", "SetBkMode", "SelectObject", "DeleteObject"} }
    });

    // ===============================
    // . Data
    // ===============================
    g.data_add_ascii("Cancel !\n", "msg1");
    g.data_add_ascii("Closed !\n", "msg2");
    g.data_add_ascii("FINI !\n", "done_msg");
    g.data_add_utf16(L"Choisissez une option :", "msg_label");
    g.data_add_utf16(L"entre ton texte ...", "msg_prefix");
    g.data_add_buffer(512,"entry_buf_w");
    g.data_add_buffer(256,"entry_buf_a");
    g.data_add_buffer(16,"buf_adr");

    // ===============================
    // . RSRC
    // ===============================
    g.rsrc_create_version(L"1.0.0.0",L"1.0.0.0",L"ARGENTROPCHER",L"boite de dialogue",L"out_dialog.exe",L"out_dialog.exe",L"@argentropcher");
    g.rsrc_create_exe_icon("frx.ico"); //icon frx.ico doit être présent à côté de l'exe
    g.rsrc_create_manifest_simple("out_dialog.exe","1.0.0.0",false,false,false,true);

    RSRC::DialogDesc d;
    d.id = 4; //id (attention, id utilisé dans le code asm)
    d.title = L"Test DialogBoxParamW"; //titre de la fenêtre
    d.x = 100; d.y = 100; d.width = 180; d.height = 80; //dimension, coordonée d'apparition
    d.italic=false; //italque (true false)
    d.size_point=12; //taille texte et fenêtre (8=standard)
    d.weight=0; //poids
    // ! lordre des controls est important, le premier est celui qui a le focus en priorité (avantage de DEFBUTTON est le enter automatique dessus même si on est sur un EDIT mi en premier)
    d.controls.push_back({RSRC::DialogControl::Type::DRAWRECT, true, 1000, L"", 0,0,180,80}); //mon fond code asm pour couleur (id 1000)
    d.controls.push_back({RSRC::DialogControl::Type::EDIT, true, 1003, L"...", 20,35,140,12}); //mi en premier de type TABSTOP pour avoir le curseur dessus
    d.controls.push_back({RSRC::DialogControl::Type::DEFBUTTON, true, 1001, L"OK", 20,55,40,16});
    d.controls.push_back({RSRC::DialogControl::Type::BUTTON, true, 1002, L"Cancel", 120,55,40,16});
    d.controls.push_back({RSRC::DialogControl::Type::DRAWRECT, true, 1004, L"", 148,2,30,30}); //rectangle dessinable avec ownerdraw

    g.rsrc_create_dialog(d);

    // ===============================
    // . External resolver pour TEXT
    // ===============================
    g.set_text_external_resolver([&](const std::string& name) -> u64 {
        // d'abord data
        u64 v = g.get_data_va(name);
        if (v != 0) return v;

        // ensuite idata (printf, etc.)
        v = g.get_idata_va("msvcrt.dll", name);
        if (v != 0) return v;
        v = g.get_idata_va("kernel32.dll", name);
        if (v != 0) return v;
        v = g.get_idata_va("user32.dll", name);
        if (v != 0) return v;
        v = g.get_idata_va("gdi32.dll", name);
        if (v != 0) return v;
        //adresse  $  pas trouvé !
        std::cout << "Pas trouvé : " << name << " !" << std::endl;
        return 0;
    });

    // ===============================
    // . ASM
    // ===============================

    //code qui est appeler par DialogBoxParamW (permet de renvoié le résultat via endDialog)
    string dialog_proc_asm =
    "push rbx\n"
    "push rsi\n"
    "push rdi\n"
    "dialog_proc:\n"
    "cmp edx, 0x110\n"          // WM_INITDIALOG
    "je .init\n"
    "cmp edx, 0x111\n"          // WM_COMMAND
    "je .command\n"
    "cmp edx, 0x2B\n"           // WM_DRAWITEM
    "je .draw_item\n"           //fait le cercle et la couleur du fond
    ".draw_exit:\n"             //normal si pas d'arg ou fin du draw
    "xor eax, eax\n"
    "jmp .exit\n"

    ".init:\n"

    //peut être enlevé pour conservé le texte fournit au départ dans rt_dialog pour edit
    "mov rdi, rcx\n"             // hwnd de la dialog sauvgarde sur rdi

    //vider l'edit avant pour afficher le texte en arrière plan de edit proprement
    "sub rsp, 28h\n"

    "mov rdx, 1003\n"
    "mov r8d, 000Ch\n"          // WM_SETTEXT
    "xor r9d, r9d\n"            // NULL
    "mov qword ptr [rsp+20h], 0\n"

    "mov rax, $SendDlgItemMessageW \n"
    "mov rax, [rax]\n"
    "call rax\n"

    "add rsp, 28h\n"

    "mov rcx, rdi\n"             // restore le hwnd de la dialog sauvgardé sur rdi
    //fin peut être enlevé

    // --- EM_SETCUEBANNER pour EDIT 1003 ---
    "sub rsp, 28h\n"                 // shadow space + align

    "mov rdx, 1003\n"                // ID de l'EDIT
    "mov r8d, 1501h\n"               // EM_SETCUEBANNER
    "mov r9d, 1\n"                   // TRUE (disparaît dès focus)

    "mov rax, $msg_prefix \n"         // wchar_t* du placeholder (texte de l'EDIT en arrière plan)
    "mov [rsp+20h], rax\n"           // LPARAM sur la stack

    "mov rax, $SendDlgItemMessageW \n"
    "mov rax, [rax]\n"
    "call rax\n"

    "add rsp, 28h\n"

    "mov eax, 1\n"
    "jmp .exit\n"

    ".command:\n"

    "movzx eax, r8w\n"           // id du bouton cliqué
    "mov rcx, rcx\n"            // hwnd
    "xor edx, edx\n"
    "mov dx, ax\n"              //id du bouton pour enddialog
    "cmp eax, 1001\n"            // OK id
    "je .ok\n"
    "cmp eax, 1002\n"            // Cancel id
    "je .cancel\n"
    "cmp eax, 2\n"               // fermeture croix ou ESC id
    "je .closed\n"
    "jmp .exit\n"                //rien exit


    ".ok:\n"
    "sub rsp, 28h\n"
    //on récupère le texte du contrôle EDIT id=1003
    "mov rdi, rcx\n"             // hwnd de la dialog sauvgarde sur rdi
    "mov edx, 1003\n"            // id du contrôle EDIT
    "mov r8, $entry_buf_w \n" // buffer wchar_t VA fourni pour stocker le texte (taille 512 car en char mais donner 256)
    "mov r9d, 256\n"             // taille max du buffer
    "mov rax, $GetDlgItemTextW \n" // GetDlgItemTextW
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "mov rcx, rdi\n"            // hwnd restoration depuis rdi
    "xor edx, edx\n"

    "jmp .convertion_func\n"    //aller au code de conversion
    ".return_convertion_func:\n"  //retour du code de conversion

    "mov rax, $entry_buf_a \n"
    "mov rdx, $buf_adr \n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire (donc le texte en ascii)
    "jmp .end_command\n"

    ".cancel:\n"
    "mov rax, $msg1 \n"
    "mov rdx, $buf_adr \n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire
    "jmp .end_command\n"

    ".closed:\n"
    "mov rax, $msg2 \n"
    "mov rdx, $buf_adr \n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire
    "jmp .end_command\n"

    ".end_command:\n"
    "mov eax, 1\n" //dire à DialogBoxParam que WM_COMMAND est traité
    "sub rsp, 28h\n"
    "mov rbx, rax\n"
    "mov rax, $EndDialog \n"
    "mov rax, [rax]\n"
    "call rax\n"

    "add rsp, 28h\n"

    "jmp .exit\n"


    ".draw_item:\n"
    "cmp r8, 1004\n"        // vérifie que c'est notre DRAWRECT (faire un cercle blue dedans)
    "je .draw_circle\n"
    "cmp r8, 1000\n"
    "je .draw_background\n"
    "jmp .draw_exit\n"

    ".draw_background:\n"
    "mov rax, r9\n"          // rax = LPDRAWITEMSTRUCT*
    "mov rbx, [rax+0x20]\n"  // rbx = HDC

    // RECT = [rax+0x10]
    "mov rax, r9\n"
    "mov eax, [rax+0x28]\n"
    "mov r12, rax\n"       // left
    "mov rax, r9\n"
    "mov eax, [rax+0x2C]\n"
    "mov r13, rax\n"       // top
    "mov rax, r9\n"
    "mov eax, [rax+0x30]\n"
    "mov r14, rax\n"       // right
    "mov rax, r9\n"
    "mov eax, [rax+0x34]\n"
    "mov r15, rax\n"       // bottom

    "sub rsp, 28h\n"
    // créer un hbrush orange RGB(255,160,5)
    "mov ecx, 0x05A0FF\n"         // COLORREF = BGR(,,)
    "mov rax, $CreateSolidBrush \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rsi, rax\n"      // sauvegarde HBRUSH
    "add rsp, 28h\n"

    //selectionne le HBRUSH creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rsi\n"        // HBRUSH creer
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rdi, rax\n"        // sauvegarde ancien brush
    "add rsp, 28h\n"

    //creer un null_pen
    "sub rsp, 28h\n"
    "mov ecx, 8\n"                // NULL_PEN = 8 dans GetStockObject
    "mov rax, $GetStockObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov r11, rax\n"              // sauvegarde le stylo nul
    "add rsp, 28h\n"

    //selectionne le null_pen creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, r11\n"        // null_pen creer
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov r10, rax\n"        // sauvegarde ancien stylo
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // Dessine le rectangle (fond)
    "mov rcx, rbx\n"     // HDC
    "mov rdx, r12\n"      // left
    "mov r8, r13\n"      // top
    "mov r9, r14\n"      // right
    "mov qword ptr [rsp+20h], r15\n" // bottom sur stack
    "mov rax, $Rectangle \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"


    //selectionne le pen d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, r10\n"        // retstorer l'ancien stylo
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne le HBRUSH d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rdi\n"        // retstorer l'ancien brush
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // nettoyer le HBRUSH creer stocker sur rsi
    "mov rcx, rsi\n"
    "mov rax, $DeleteObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne la couleur du texte
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"              // HDC
    "mov edx, 0x000000\n"         // noir
    "mov rax, $SetTextColor \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //fond transparent
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"             // HDC
    "mov edx, 1\n"               // TRANSPARENT
    "mov rax, $SetBkMode \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //calculer la longueur exacte de la chaîne pour afficher le texte avec lstrlenW
    "sub rsp, 28h\n"
    "mov rcx, $msg_label \n"
    "mov rax, $lstrlenW \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"
    //reponse dans rax, pas besoin de le bouger vu que appeller après

    //texte du label mais avec le font correct pas comme si on le met dans rt_dialog LABEL (même position)
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"               // HDC
    "mov rdx, 0x30\n"              // x
    "mov r8, 0x35\n"              // y
    "mov r9, $msg_label \n"     // texte UTF-16
    "mov qword ptr [rsp+20h], rax\n" // c  (longueur exacte de la chaine)
    "mov rax, $TextOutW \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "jmp .draw_exit\n"


    ".draw_circle:\n"
    "mov rax, r9\n"          // rax = LPDRAWITEMSTRUCT*
    "mov rbx, [rax+0x20]\n"  // rbx = HDC

    // RECT = [rax+0x10]
    "mov rax, r9\n"
    "mov eax, [rax+0x28]\n"
    "mov r12, rax\n"       // left
    "mov rax, r9\n"
    "mov eax, [rax+0x2C]\n"
    "mov r13, rax\n"       // top
    "mov rax, r9\n"
    "mov eax, [rax+0x30]\n"
    "mov r14, rax\n"       // right
    "mov rax, r9\n"
    "mov eax, [rax+0x34]\n"
    "mov r15, rax\n"       // bottom

    "sub rsp, 28h\n"
    // créer un brush bleu RGB(0,0,255)
    "mov ecx, 0xFF0000\n"         // COLORREF = BGR(,,)
    "mov rax, $CreateSolidBrush \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rsi, rax\n"      // sauvegarde HBRUSH
    "add rsp, 28h\n"

    //selectionne le HBRUSH creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rsi\n"        // HBRUSH creer (bleu)
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rdi, rax\n"        // sauvegarde ancien brush
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // Dessine le cercle
    "mov rcx, rbx\n"     // HDC
    "mov rdx, r12\n"      // left
    "mov r8, r13\n"      // top
    "mov r9, r14\n"      // right
    "mov qword ptr [rsp+20h], r15\n" // bottom sur stack
    "mov rax, $Ellipse \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne le HBRUSH d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rdi\n"        // retstorer l'ancien brush
    "mov rax, $SelectObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // nettoyer le HBRUSH creer stocker sur rsi
    "mov rcx, rsi\n"
    "mov rax, $DeleteObject \n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "jmp .draw_exit\n"

    ".exit:\n"
    "pop rdi\n"
    "pop rsi\n"
    "pop rbx\n"
    "ret\n"


    //convertion utf-16 en ascii
    ".convertion_func:\n"
    "mov rsi, $entry_buf_w \n"           // source UTF-16
    "mov rdi, $entry_buf_a \n"     // destination ASCII

    ".convert_utf16_to_ascii:\n"
    "mov ax, word ptr [rsi]\n"       // lire wchar_t
    "test ax, ax\n"
    "je .done_convert\n"             // fin si 0

    "cmp ax, 0x007F\n"
    "ja .non_ascii\n"

    "mov byte ptr [rdi], al\n"       // ASCII direct
    "jmp .next_char\n"

    ".non_ascii:\n"
    "mov byte ptr [rdi], '?'\n"      // remplacement

    ".next_char:\n"
    "add rsi, 2\n"                   // wchar_t++
    "inc rdi\n"                      // char++
    "jmp .convert_utf16_to_ascii\n"

    ".done_convert:\n"
    "mov byte ptr [rdi], 0\n"        // null-terminate ASCII
    "xor rsi, rsi\n"
    "xor rdi, rdi\n"
    "mov rdi, 1\n"
    "jmp .return_convertion_func\n"

    ;

    g.text_add_function("dialog_proc_asm", dialog_proc_asm);

    std::string main_asm =
        // prologue for main - reserve shadow + extra stack space
        "sub rsp, 28h\n"

        // hInstance = GetModuleHandleW(NULL)
        "xor rcx, rcx\n"
        "mov rax, $GetModuleHandleW \n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // DialogBoxParamW(hInst, ID=1, NULL, dialog_proc, 0)
        "mov rcx, rax\n"                        // hInstance
        "mov rdx, 4\n"                          // MAKEINTRESOURCEW(4)   (on a donné comme id 4 la rt_dialog)
        "xor r8, r8\n"                          // parent = NULL
        "mov r9, $dialog_proc_asm \n" //nom du script de la fenêtre (addr)

        "mov qword ptr [rsp+20h], 0\n"

        "mov rax, $DialogBoxParamW \n"
        "mov rax, [rax]\n"
        "call rax\n"
        "mov rbx, $buf_adr \n"  //récupère l'adresse de la réponse dialog dans le buffer

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // Print final message: puts("FINI !\n")
        "mov rcx, $done_msg \n"
        "mov rax, $puts \n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // appeler puts (affiche message) keystone ne comprend pas donc ignore et cut en 2 main alors que c'est la suite
        "mov rax, [rbx]\n"  //reprend la réponse (adresse de rbx)
        "mov rcx, rax\n"
        "mov rax, $puts \n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // ExitProcess(0)
        "xor ecx, ecx\n"
        "mov rax, $ExitProcess \n"
        "mov rax, [rax]\n"
        "call rax\n"
        "ret\n";        //terminer

    g.text_add_function("main", main_asm);

    // ===============================
    // . Push sections
    // ===============================
    g.push_section("idata");
    g.push_section("data");
    g.push_section("text"); //text doit être après ou alors on doit utilisé g.update_section(); après toutes les sections utilisé
    g.push_section("rsrc");

    // ===============================
    // . Entry point
    // ===============================
    u32 entry_va = g.get_text_rva("main");
    if (entry_va == 0) {
        std::cout << "Erreur : entry point non résolu" << std::endl;
        return 1;
    }

    g.set_addr_entry_point(entry_va);

    // ===============================
    // . Build
    // ===============================
    g.set_exe_name("out_dialog.exe");
    g.set_cmd(true);
    g.buid_exe();

    std::cout << "EXE généré : out_dialog.exe" << std::endl;
    return 0;
}
