#include "pe_gen_window64.hpp"

//g++ -std=c++17 test_lib_window64.cpp -lkeystone -o test_lib_window64.exe

int main() {
    GESTION g;

    // ===============================
    // . Imports
    // ===============================
    g.idata_add_imports({
        { "msvcrt.dll", { "printf" } },
        { "kernel32.dll", { "ExitProcess" } }
    });

    // ===============================
    // . Data
    // ===============================
    g.data_add_ascii("Hello from custom linker !\n", "msg");

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
        //adresse  $  pas trouvé !
        return 0;
    });

    // ===============================
    // . ASM
    // ===============================
    g.text_add_function("main", R"(
        mov rax, $print
        call rax
        mov rax, $exit
        call rax
        ret
    )");

    g.text_add_function("print", R"(
        sub rsp, 30h

        mov rcx, $msg
        mov rax, $printf
        mov rax, [rax]
        call rax

        add rsp, 30h
        ret
    )");

    g.text_add_function("exit", R"(
        sub rsp, 30h
        xor ecx, ecx
        mov rax, $ExitProcess
        mov rax, [rax]
        call rax
        add rsp, 30h
        ret
    )");

    // ===============================
    // . Push sections
    // ===============================
    g.push_section("idata");
    g.push_section("data");
    g.push_section("text");

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
    g.set_exe_name("test_printf.exe");
    g.set_cmd(true);
    g.buid_exe();

    std::cout << "EXE généré : test_printf.exe" << std::endl;
    return 0;
}
