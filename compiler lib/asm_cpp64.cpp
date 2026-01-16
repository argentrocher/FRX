#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>

#include "pe_gen_window64.hpp"

//g++ -std=c++17 asm_cpp64.cpp -lkeystone -o asm_cpp64.exe

//variable global
std::string the_global_entry_point_name = "main"; //nom du point d'entrer du fichier
bool is_debug = false;  //afficher les information de debugage du fichier constructeur
bool include_func_asm_defaut = false; //inclure les fonctions par défaut dans l'asm

struct SEP_SECTION {
    std::string name;                 // ex: ".text", ".data", ".idata"
    std::vector<std::string> lines;   // lignes nettoyées
};

//stock les noms des dll
using IDATA_IMPORTS = std::vector<std::pair<std::string, std::vector<std::string>>>;
struct IDATA_CONTEXT {
    IDATA_IMPORTS imports;
};

static inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

void suppr_more_space(std::string& str) {
    if (str.empty()) {
        return; // Si la chaîne est vide, rien à faire
    }

    size_t pos = 0;
    bool espaceTrouve = false;

    // Parcourir la chaîne pour supprimer les espaces multiples
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == ' ') {
            if (!espaceTrouve) {
                str[pos++] = str[i]; // Garder le premier espace
                espaceTrouve = true;
            }
            // Ignorer les espaces suivants
        } else {
            str[pos++] = str[i]; // Copier le caractère
            espaceTrouve = false;
        }
    }

    // Supprimer les caractères restants après la nouvelle position
    str.erase(pos);
}

static inline bool starts_with(const std::string& s, const std::string& prefix) {
    return s.rfind(prefix, 0) == 0;
}

static inline std::string strip_comments(const std::string& line) {
    std::string out = line;

    // couper sur //
    size_t pos = out.find("//");
    if (pos != std::string::npos) {
        out = out.substr(0, pos);
    }

    // couper sur ;
    pos = out.find(';');
    if (pos != std::string::npos) {
        out = out.substr(0, pos);
    }

    return trim(out);
}

static inline std::vector<std::string> split(const std::string& s, char delim = ' ', bool respect_quotes = false)
{
    std::vector<std::string> elems;
    std::string token;
    bool in_quotes = false;

    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];

        // Gestion des guillemets avec échappement
        if (respect_quotes && c == '"') {
            // Compter le nombre de \ juste avant
            size_t backslash_count = 0;
            size_t j = i;
            while (j > 0 && s[j - 1] == '\\') {
                backslash_count++;
                j--;
            }

            // Si nombre pair de \ => " réel (non échappé)
            if ((backslash_count % 2) == 0) {
                in_quotes = !in_quotes; // toggle uniquement si pas échappé
            }

            token += c;
        }
        else if (!in_quotes && c == delim) {
            token = trim(token);
            if (!token.empty())
                elems.push_back(token);
            token.clear();
        }
        else {
            token += c;
        }
    }

    token = trim(token);
    if (!token.empty())
        elems.push_back(token);

    return elems;
}


static inline std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static inline std::wstring to_wstring(const std::string& s) {
    std::wstring ws(s.begin(), s.end());
    return ws;
}

//pour les \n \t \r dans les data
static std::string parse_escaped_string(const std::string& s)
{
    std::string result;
    result.reserve(s.size());

    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[i + 1];
            switch (next) {
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                case 'r':  result += '\r'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"'; break;
                default:   result += next; break; // juste ignorer \ inconnu
            }
            ++i; // saute le caractère suivant
        }
        else {
            result += s[i];
        }
    }

    return result;
}

//pour les true false en texte
static bool parse_bool(const std::string& s)
{
    if (s == "true" || s == "1") return true;
    if (s == "false" || s == "0") return false;
    std::cerr << "bool invalide : " << s << " (convertit en false)" << std::endl;
    return false;
}

//pour les nombres
static inline bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (!isdigit((unsigned char)c)) return false;
    return true;
}

//pour les nombres
static inline int to_int_checked(const std::string& s, const std::string& err) {
    if (!is_number(s)) {
        std::cerr << err << " : " << s << std::endl;
        throw std::runtime_error("parse error");
    }
    return std::stoi(s);
}

//pour les type de control
static inline RSRC::DialogControl::Type parse_control_type(const std::string& s) {
    if (s == "BUTTON")     return RSRC::DialogControl::Type::BUTTON;
    if (s == "DEFBUTTON") return RSRC::DialogControl::Type::DEFBUTTON;
    if (s == "LABEL")     return RSRC::DialogControl::Type::LABEL;
    if (s == "EDIT")      return RSRC::DialogControl::Type::EDIT;
    if (s == "FILLRECT")  return RSRC::DialogControl::Type::FILLRECT;
    if (s == "FRAMERECT") return RSRC::DialogControl::Type::FRAMERECT;
    if (s == "DRAWRECT")  return RSRC::DialogControl::Type::DRAWRECT;

    std::cerr << "Type de control inconnu : " << s << std::endl;
    throw std::runtime_error("parse error");
}

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


    // asm_ascii_utf16 : Convertit une chaîne ASCII (RCX) en UTF-16 (RDX)
    // Convertit une chaîne ASCII (RCX) en UTF-16 (RDX)
    //; RCX = adresse de la chaîne ASCII source
    //; RDX = adresse du tampon UTF-16 de destination
    //; R8 = longueur maximale (si 0, utilise asm_strlen)
    g.text_add_function("asm_ascii_utf16", R"(
    sub rsp, 40h

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

    add rsp, 40h
    ret
)");

    //; RCX = adresse de la chaîne UTF-16 source
    //; RDX = adresse du tampon ASCII de destination
    //; R8 = longueur maximale (si 0, utilise asm_wstrlen)
    // Convertit une chaîne UTF-16 (RCX) en ASCII (RDX)
    g.text_add_function("asm_utf16_ascii", R"(
    sub rsp, 40h

    mov rdi, rdx

    test r8, r8
    jnz skip_strlen
    mov rax, $asm_wstrlen
    call rax
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

    add rsp, 40h
    ret
)");


    // asm_addr_ascii : Convertit une adresse (RCX) en chaîne ASCII (16 octets) et écrit dans le buffer (RDX)
    //; RCX = adresse à convertir
    //; RDX = adresse du buffer (17 octets)
    //: R8 = copie de charactère (0=16 sinon R8)
    g.text_add_function("asm_addr_ascii", R"(
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

    ret
)");

    // asm_addr_utf16 : Convertit une adresse (RCX) en chaîne UTF-16 (32 octets) et écrit dans le buffer (RDX)
    //; RCX = adresse à convertir
    //; RDX = adresse du buffer (32 octets)
    //: R8 = copie de charactère (0=16 sinon R8)
    g.text_add_function("asm_addr_utf16", R"(
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

    ret
)");

    g.text_add_function("asm_addr_int_ascii", R"(
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
    ret
)");

    g.text_add_function("asm_addr_int_utf16", R"(
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
    ret
)");

    //; RCX = char* source
    //; R8  = longueur max (0 = utiliser asm_strlen)
    //; RAX = résultat
    g.text_add_function("asm_addr_ascii_int", R"(
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
    ret
)");

    //; RCX = wchar_t* source
    //; R8  = longueur max (0 = utiliser asm_wstrlen)
    //; RAX = résultat
    g.text_add_function("asm_addr_utf16_int", R"(
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
    ret
)");

    //; XMM0 = double
    //; RDX = buffer
    //; R8 = num after comma (-1 pour prendre la valeur par défaut, sinon n'affiche pas de virgule)
    g.text_add_function("asm_addr_double_ascii", R"(
    push rbx

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
    pop rbx
    ret
)");

    //; RCX = char*
    //; RAX = double (dans xmm0)
    g.text_add_function("asm_addr_ascii_double", R"(
    push rbx

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
    pop rbx
    ret
)");

}



//idata debut
bool parse_idata_section(const SEP_SECTION& section, IDATA_IMPORTS& out_imports)
{
    // section.name doit être ".idata"
    for (const auto& line : section.lines) {
        auto tokens = split(line, ' ');
        if (tokens.size() < 2) {
            std::cerr << "WARNING idata: ligne invalide : " << line << std::endl;
            continue;
        }

        std::string dll_name = tokens[0];
        std::vector<std::string> funcs;

        for (size_t i = 1; i < tokens.size(); ++i) {
            funcs.push_back(tokens[i]);
        }

        out_imports.emplace_back(dll_name, funcs);
    }

    return true;
}

void apply_idata_to_gestion(GESTION& g, const IDATA_IMPORTS& imports)
{
    if (imports.empty()) return;
    g.idata_add_imports(imports);
}

void dispatch_idata_section(const SEP_SECTION& section, GESTION& g, IDATA_CONTEXT& ctx)
{
    IDATA_IMPORTS imports;
    parse_idata_section(section, imports);

    ctx.imports = imports;          // stock pour resolver
    apply_idata_to_gestion(g, imports);
}
//fin idata

//debut data
bool parse_data_section(const SEP_SECTION& section, GESTION& g)
{
    // section.name doit être ".data"
    for (const auto& line : section.lines) {

        auto tokens = split(line, ' ', true);
        if (tokens.empty()) continue;

        const std::string& cmd = tokens[0];

        // ===============================
        // ASCII
        // ascii key "text"
        // ===============================
        if (cmd == "ascii") {
            if (tokens.size() < 3) {
                std::cerr << "data ascii invalide : " << line << std::endl;
                continue;
            }

            std::string key = tokens[1];

            // reconstituer la string si espaces
            std::string raw;
            for (size_t i = 2; i < tokens.size(); ++i) {
                if (i > 2) raw += " ";
                raw += tokens[i];
            }

            std::string text = parse_escaped_string(unquote(raw));

            g.data_add_ascii(text, key);
        }

        // ===============================
        // UTF16
        // utf16 key "text"
        // ===============================
        else if (cmd == "utf16") {
            if (tokens.size() < 3) {
                std::cerr << "data utf16 invalide : " << line << std::endl;
                continue;
            }

            std::string key = tokens[1];

            std::string raw;
            for (size_t i = 2; i < tokens.size(); ++i) {
                if (i > 2) raw += " ";
                raw += tokens[i];
            }

            std::string text = parse_escaped_string(unquote(raw));
            std::wstring wtext = to_wstring(text);

            g.data_add_utf16(wtext, key);
        }

        // ===============================
        // BUFFER
        // buffer key size
        // ===============================
        else if (cmd == "buffer") {
            if (tokens.size() != 3) {
                std::cerr << "data buffer invalide : " << line << std::endl;
                continue;
            }

            std::string key = tokens[1];
            size_t size = std::stoul(tokens[2]);

            g.data_add_buffer(size, key);
        }

        else {
            std::cerr << "Commande data inconnue : " << cmd << std::endl;
        }
    }
    return true;
}
//fin data

//debut text
bool parse_text_section(const SEP_SECTION& section, GESTION& g)
{
    bool in_proc = false;
    std::string current_name;
    std::string current_body;

    for (size_t i = 0; i < section.lines.size(); ++i) {
        const std::string& line = section.lines[i];

        auto tokens = split(line, ' ');
        if (tokens.empty()) continue;

        // ===============================
        // Début de proc
        // proc name
        // ===============================
        if (!in_proc && tokens[0] == "proc") {
            if (tokens.size() != 2) {
                std::cerr << "proc invalide : " << line << std::endl;
                return false;
            }

            in_proc = true;
            current_name = tokens[1];
            current_body.clear();
            continue;
        }

        // ===============================
        // Fin de proc
        // end name
        // ===============================
        if (in_proc && tokens[0] == "end") {
            if (tokens.size() != 2) {
                std::cerr << "end invalide : " << line << std::endl;
                return false;
            }

            std::string end_name = tokens[1];

            if (end_name != current_name) {
                std::cerr << "end ne correspond pas au proc : " << end_name
                          << " (attendu " << current_name << ")" << std::endl;
                return false;
            }

            // Envoi au moteur
            g.text_add_function(current_name, current_body);

            // reset
            in_proc = false;
            current_name.clear();
            current_body.clear();
            continue;
        }

        // ===============================
        // Lignes internes au proc
        // ===============================
        if (in_proc) {
            current_body += line;
            current_body += "\n";
        }
        else {
            std::cerr << "WARNING : ligne hors proc ignorée : " << line << std::endl;
        }
    }

    if (in_proc) {
        std::cerr << "Erreur : proc non terminé : " << current_name << std::endl;
        return false;
    }

    return true;
}
//fin text

//debut rsrc
bool parse_rsrc_section(const SEP_SECTION& section, GESTION& g)
{
    RSRC::DialogDesc current_dialog;
    bool has_dialog = false;

    for (const auto& line : section.lines) {
        auto tokens = split(line, ' ', true);
        if (tokens.empty()) continue;

        const std::string& cmd = tokens[0];

        // ===============================
        // DIALOG
        // dialog id "title" x y w h "font" charset [size] [italic]
        // ===============================
        try {
        if (cmd == "dialog") {
            if (tokens.size() < 9 || tokens.size() > 11) {
                std::cerr << "dialog invalide : " << line << std::endl;
                return false;
            }

            RSRC::DialogDesc d;

            d.id = (u16)to_int_checked(tokens[1], "dialog id invalide");
            d.title = to_wstring(parse_escaped_string(unquote(tokens[2])));
            d.x = (u16)to_int_checked(tokens[3], "dialog x invalide");
            d.y = (u16)to_int_checked(tokens[4], "dialog y invalide");
            d.width  = (u16)to_int_checked(tokens[5], "dialog width invalide");
            d.height = (u16)to_int_checked(tokens[6], "dialog height invalide");

            d.font = to_wstring(parse_escaped_string(unquote(tokens[7])));
            d.character_set = (u16)to_int_checked(tokens[8], "dialog charset invalide");

            d.size_point = (tokens.size() >= 10) ? (u16)to_int_checked(tokens[9], "dialog size_point invalide") : 8;
            d.italic = (tokens.size() >= 11) ? parse_bool(tokens[10]) : false;

            // valeurs fixes (comme dans ton exemple)
            d.weight = 0;

            current_dialog = d;
            current_dialog.controls.clear();
            has_dialog = true;
        }

        // ===============================
        // CONTROL
        // control dialog_id TYPE id "text" x y w h
        // ===============================
        else if (cmd == "control") {
            if (tokens.size() != 9) {
                std::cerr << "control invalide : " << line << std::endl;
                return false;
            }

            if (!has_dialog) {
                std::cerr << "control sans dialog avant : " << line << std::endl;
                return false;
            }

            u16 dialog_id = (u16)to_int_checked(tokens[1], "control dialog id invalide");
            if (dialog_id != current_dialog.id) {
                std::cerr << "control sur mauvais dialog (attendu id "
                          << current_dialog.id << ", reçu id " << dialog_id << ")" << std::endl;
                return false;
            }

            RSRC::DialogControl c;
            c.type = parse_control_type(tokens[2]);
            c.enabled = true;
            c.id = (u16)to_int_checked(tokens[3], "control id invalide");
            c.text = to_wstring(parse_escaped_string(unquote(tokens[4])));
            c.x = (u16)to_int_checked(tokens[5], "control x invalide");
            c.y = (u16)to_int_checked(tokens[6], "control y invalide");
            c.width  = (u16)to_int_checked(tokens[7], "control width invalide");
            c.height = (u16)to_int_checked(tokens[8], "control height invalide");

            current_dialog.controls.push_back(c);
        }

        // ===============================
        // FLUSH DIALOG (quand on rencontre autre chose)
        // ===============================
        else {
            if (has_dialog) {
                g.rsrc_create_dialog(current_dialog);
                has_dialog = false;
            }
        }
        } catch (...) {
            std::cout << "Attendu : \ndialog 'INT id' 'STRING title' 'INT x' 'INT y' 'INT width' 'INT height' 'STRING font' 'INT charset_set' ['INT size_point'] ['BOOL italic']" << std::endl;
            std::cout << "Peut suivre ligne suivante :\ncontrol 'INT id_dialog_ref' 'TYPE object' 'INT id' 'STRING text' 'INT x' 'INT y' 'INT width' 'INT height'\ninfo : TYPE peut être : BUTTON , DEFBUTTON , EDIT , LABEL , FILLRECT , FRAMERECT , DRAWRECT\n"<< std::endl;
            return false;
        }

        if (cmd == "dialog" || cmd == "control") {
            continue;
        }
        // ===============================
        // ICON
        // icon "path.ico"
        // ===============================
        else if (cmd == "icon") {
            if (tokens.size() != 2) {
                std::cerr << "rsrc icon invalide : " << line << std::endl;
                return false;
            }

            std::string path = parse_escaped_string(unquote(tokens[1]));
            g.rsrc_create_exe_icon(path);
        }

        // ===============================
        // VERSION SIMPLE
        // version_simple "1.0.0.0" "app.exe" "copyright"
        // ===============================
        else if (cmd == "version_simple") {
            if (tokens.size() < 1 || tokens.size() > 4) {
                std::cerr << "rsrc version_simple invalide : " << line << std::endl;
                return false;
            }

            std::wstring fileVersion = (tokens.size() >= 2) ? to_wstring(parse_escaped_string(unquote(tokens[1]))) : L"1.0.0.0";
            std::wstring exeName     = (tokens.size() >= 3) ? to_wstring(parse_escaped_string(unquote(tokens[2]))) : L"out.exe";
            std::wstring copyright   = (tokens.size() >= 4) ? to_wstring(parse_escaped_string(unquote(tokens[3]))) : L"argentropcher";

            g.rsrc_create_version_simple(fileVersion, exeName, copyright);
        }

        // ===============================
        // VERSION FULL
        // version_full "fileVer" "prodVer" "company" "desc" "product" "orig" "copyright"
        // ===============================
        else if (cmd == "version_full") {
            if (tokens.size() != 8) {
                std::cerr << "rsrc version_full invalide : " << line << std::endl;
                return false;
            }

            auto w = [&](size_t i) {
                return to_wstring(parse_escaped_string(unquote(tokens[i])));
            };

            g.rsrc_create_version(
                w(1), w(2), w(3), w(4), w(5), w(6), w(7)
            );
        }

        // ===============================
        // MANIFEST SIMPLE
        // manifest_simple "exe" "ver" true true false true
        // ===============================
        else if (cmd == "manifest_simple") {
            if (tokens.size() != 7) {
                std::cerr << "rsrc manifest_simple invalide : " << line << std::endl;
                return false;
            }

            std::string exeName = parse_escaped_string(unquote(tokens[1]));
            std::string version = parse_escaped_string(unquote(tokens[2]));

            bool dpiAware      = parse_bool(tokens[3]);
            bool perMonitorV2  = parse_bool(tokens[4]);
            bool requireAdmin  = parse_bool(tokens[5]);
            bool commonV6      = parse_bool(tokens[6]);

            g.rsrc_create_manifest_simple(exeName, version, dpiAware, perMonitorV2, requireAdmin, commonV6);
        }

        // ===============================
        // MANIFEST XML
        // manifest_xml "<xml...>"
        // ===============================
        else if (cmd == "manifest_xml") {
            if (tokens.size() < 2) {
                std::cerr << "rsrc manifest_xml invalide : " << line << std::endl;
                return false;
            }

            // reconstituer la string complète
            std::string raw;
            for (size_t i = 1; i < tokens.size(); ++i) {
                if (i > 1) raw += " ";
                raw += tokens[i];
            }

            std::string xml = parse_escaped_string(unquote(raw));
            g.rsrc_create_manifest(xml);
        }

        else {
            std::cerr << "Commande rsrc inconnue : " << cmd << std::endl;
            return false;
        }
    }

    //si on finit par un dialog
    if (has_dialog) {
        g.rsrc_create_dialog(current_dialog);
        has_dialog = false;
    }

    return true;
}
//fin rsrc

//parseur de section
bool parse_asm_file_sections(const std::string& path, std::vector<SEP_SECTION>& out_sections)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Erreur : impossible d'ouvrir le fichier : " << path << std::endl;
        return false;
    }

    std::string line;

    // ===============================
    // Vérification première ligne
    // ===============================
    if (!std::getline(file, line)) {
        std::cerr << "Erreur : fichier vide !" << std::endl;
        return false;
    }

    line = trim(line);

    if (line != "ASM64CPP") {
        std::cout << "WARNING : ce code asm n'est pas forcément compatible avec ASM64CPP !" << std::endl;
    }

    SEP_SECTION* current_section = nullptr;

    // ===============================
    // Lecture ligne par ligne
    // ===============================
    while (std::getline(file, line)) {
        line = strip_comments(line);
        if (line.empty()) continue;

        // ===============================
        // GLOBAL ENTRY POINT (avant sections)
        // ===============================
        if (!current_section && starts_with(line, "global")) {
            std::string rest = trim(line.substr(6)); // après "global"
            // enlever les :
            rest.erase(std::remove(rest.begin(), rest.end(), ':'), rest.end());
            rest = trim(rest);

            if (!rest.empty()) {
                the_global_entry_point_name = rest;
                if (is_debug) {
                    std::cout << "[*] Global entry point détecté : " << the_global_entry_point_name << std::endl;
                }
            }

            continue; // ne pas traiter comme une ligne normale
        }

        //cas ou il y a un include defaut :
        if (!current_section && starts_with(line,"include")) {
            std::string l = trim(line);
            suppr_more_space(l); //supprimer les espaces multiples collé
            if (starts_with(l, "include defaut")) {
                if (l.size() == 14 || (l.size() == 15 && l[14] == ':') || (l.size() == 16 && isspace((unsigned char)l[14]) && l[15] == ':')) {
                    include_func_asm_defaut=true;
                    continue;
                }
            }
            if (starts_with(l, "include default")) {
                if (l.size() == 15 || (l.size() == 16 && l[15] == ':') || (l.size() == 17 && isspace((unsigned char)l[15]) && l[16] == ':')) {
                    include_func_asm_defaut=true;
                    continue;
                }
            }
        }

        // section detection
        if (starts_with(line, "section ")) {
            // format attendu : section .text
            std::string sec_name = trim(line.substr(7)); // après "section"
            SEP_SECTION sec;
            sec.name = sec_name;
            out_sections.push_back(sec);
            current_section = &out_sections.back();
            continue;
        }

        if (!current_section) {
            std::cerr << "WARNING : ligne hors section ignorée : " << line << std::endl;
            continue;
        }

        current_section->lines.push_back(line);
    }

    return true;
}

//resolver de la lib
void setup_idata_resolver(GESTION& g, const IDATA_CONTEXT& ctx)
{
    g.set_text_external_resolver([&g, &ctx](const std::string& name) -> u64 {

        // 1) DATA
        u64 v = g.get_data_va(name);
        if (v != 0) return v;

        // 2) IDATA (parcours des DLL déclarées)
        for (const auto& dll : ctx.imports) {
            const std::string& dll_name = dll.first;
            v = g.get_idata_va(dll_name, name);
            if (v != 0) return v;
        }

        // 3) pas trouvé
        std::cout << "Pas trouvé (resolver) : " << name << std::endl;
        return 0;
    });
}

int main(int argc, char* argv[])
{
    //configurer l'encodage affichage
    SetConsoleOutputCP(1252);
    SetConsoleCP(1252);

    if (argc < 3) {
        std::cout << "Usage:\n";
        std::cout << "  " << argv[0] << " <source.asm> <output.exe> [--see_all_exception] [--cmd/--gui] [--debug] [--no_test_code]\n";
        return 1;
    }

    std::string asm_file;
    std::string output_exe;

    bool see_all_exception = false;
    bool use_cmd = false;
    bool test_a_code = true; //le test du code est activé par défaut

    // --- Arguments obligatoires ---
    asm_file = argv[1];
    output_exe = argv[2];

    // --- Options facultatives ---
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--see_all_exception") {
            see_all_exception = true;
        }
        else if (arg == "--cmd") {
            use_cmd = true;
        }
        else if (arg == "--gui") {
            use_cmd = false;
        }
        else if (arg == "--debug") {
            is_debug = true;
        }
        else if (arg == "--info") {
            std::cout << "Usage:\n";
            std::cout << "  " << argv[0] << " <source.asm> <output.exe> [--see_all_exception] [--cmd/--gui] [--debug] [--no_test_code]\n";
            std::cout << "source.asm = fichier de code asm\noutput.exe = nom du fichier sur lequel le resultat de l'opération est fait\n--see_all_exception = voir les logs de l'appi du compilateur\n--cmd != --gui = permet d'avoir le cmd ou non\n --debug = voir les information de débuggage de lecture du fichier configuration\n --no_test_code = désactive le débuggage des instruction (si on a déjà tester, permet d'accèlérer le constructeur, option déconseiller !)" <<std::endl ;
        }
        else if (arg == "--no_test_code") {
            test_a_code = false;
        }
        else {
            std::cout << "Option inconnue : " << arg << std::endl;
            return 1;
        }
    }

    if (is_debug) {
    // --- Debug affichage (optionnel mais utile) ---
    std::cout << "[*] ASM file   : " << asm_file << std::endl;
    std::cout << "[*] Output EXE : " << output_exe << std::endl;
    std::cout << "[*] CMD mode   : " << (use_cmd ? "ON" : "OFF") << std::endl;
    std::cout << "[*] See all exception : " << (see_all_exception ? "ON" : "OFF") << std::endl;
    }

    // ===============================
    // Lecture + découpage ASM
    // ===============================
    std::vector<SEP_SECTION> sections;
    if (!parse_asm_file_sections(asm_file, sections)) {
        std::cerr << "Erreur parsing ASM." << std::endl;
        return 1;
    }

    if (is_debug) {
    std::cout << "[*] Sections détectées :" << std::endl;
    for (auto& s : sections) {
        std::cout << "  - " << s.name << " (" << s.lines.size() << " lignes)" << std::endl;
    }
    }

    // ===============================
    // Init de ton moteur
    // ===============================
    GESTION g;

    if (see_all_exception) {
        g.set_see_not_fatal_exception(true);
    }

    g.set_cmd(use_cmd);

    g.set_test_code(test_a_code); //activer le teste du code

    //idata
    IDATA_CONTEXT idata_ctx;
    for (const auto& sec : sections) {
        if (sec.name == ".idata") {
            dispatch_idata_section(sec, g, idata_ctx);
            break;
        }
    }
    setup_idata_resolver(g, idata_ctx);

    //data
    for (const auto& sec : sections) {
        if (sec.name == ".data") {
            if (!parse_data_section(sec, g)) {
                std::cerr << "erreur fatale data !"<< std::endl;
                return 1;
            }
            break;
        }
    }

    //ajoute les functions par defaut si demander
    if (include_func_asm_defaut) {
        inject_default_asm_functions(g);
    }
    // text
    for (const auto& sec : sections) {
        if (sec.name == ".text") {
            if (!parse_text_section(sec, g)) {
                std::cerr << "erreur fatale text !"<< std::endl;
                return 1;
            }
            break;
        }
    }

    // rsrc
    for (const auto& sec : sections) {
        if (sec.name == ".rsrc") {
            if (!parse_rsrc_section(sec, g)) {
                std::cerr << "erreur fatale rsrc !" << std::endl;
                return 1;
            }
            break;
        }
    }


    for (const auto& sec : sections) {
        if (sec.name == ".text" || sec.name == ".data" || sec.name == ".idata" || sec.name == ".rsrc") {
            g.push_section(sec.name);
        }
    }

    g.update_section();

    g.set_exe_name(output_exe);

    u32 entry_va = g.get_text_rva(the_global_entry_point_name);
    if (entry_va == 0) {
        std::cerr << "Erreur : entry point non résolu ou pas de fonction " << the_global_entry_point_name << " (obligatoire !)" << std::endl;
        return 1;
    }
    g.set_addr_entry_point(entry_va);
    g.buid_exe();

    std::cout << "OK !\n" << asm_file << " -> " << output_exe << std::endl;

    return 0;
}
