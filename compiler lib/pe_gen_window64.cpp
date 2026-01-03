/*
PE BUILDER BY ARGENTROPCHER (ASSIGNE AU COMPTE GOOGLE ARGENTROPCHER)

Si vous utiliser ce code, il est seulement obligatoire de citer que vous utiliser "keystone" pour l'assembleur si vous utiliser les exemples et de citer ce depot "github" ou "BY ARGENTROPCHER".
PS : merci à "keystone" pour sont assembleur sinon, ecrire les bit à la main est impossible.

ce code est testé avec mingw g++, et est senser être compatible avec msvsc.

Ceci est un constructeur de PE 64 bits windows en assembleur, regarder les exemples des section main pour créer du code,
les classes gère le constructeur et le constructeur inclu automatiquement la section .text (le code asm compiler).

les autres sections spécial de windows gerer :
- idata pour importer des  fonctions dll (normalement seul obligatoire et suffisant si le code ne fait pas d'exeption par section, un espace memoire .data (pas de class mais montrer dans les exemples pour la creer) .idata pour l'importations des dll suffisent)
- rsrc pour icon ico version_info dans détail windows, manifest (paramètre de configuration) et boite de dialog ecrit dans l'executable non dynamique (pour faire des fenêtres dynamique, utiliser un code asm complet ; pas d'exemple ici)


 Ce code est plutôt simple et permet de creer des codes machine sans trop de difficulté,
 j'ai chercher un constructeur en C/C++/C# sur internet, mais cela est totalement introuvable,
 ou alors beaucoup trop complexe pour chercher les fichiers constructeurs de gcc par exemple, surtout que ce n'est pas écrit en C.

Ce code n'est pas très optimiser dans les controls utilisateurs pour la création de fenêtre, on écrit trop,
un fichier hpp sera disponible pour obtimiser les appels des sections et la construction, mais la logique du constructeur d'executable x8664 windows restera la même.

(valide en fonction des codes/sections utilisés de windows XP au dernier windows (actuelement windows 11) arichitecture 64 bit uniquement)

6 exemples sont proposés, de simple à compliquer, il faut enlevé les   ' / * ' et ' \ * ' qui les entours.
 les exemples les plus évolués sont les dernier 4, 5 et 6.
 il est recommander de comprendre les exemples précédents et de connaître l'assembleur.
 --> l'assembleur lien utile : https://www.lacl.fr/tan/asm .


ce code est libre de droits, mais l'auteur ne pourra être tenu d'aucun dégat cause à un ordinateur windows dans le but de
piratage ou/et en cas de création de code/section dangereuse/instable/utilisant des droits administrateurs.

PS : il est conseiller d'utiliser une machine virtuel pour du code utilisant des appels os ou des droits administrateurs.
*/


#include <windows.h>          //rajouter pour les valeurs des constantes
#include "keystone/keystone.h"      //si vous souhaitez utiliser un autre asm 64 bits windows, c'est possible, il faut juste retirer la fonction global vector<u8> assemble(const char* code)

//lib incluse avec mingw, verifier la compatibilité si msvsc.
#include <iomanip>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <map>
#include <algorithm>
#include <chrono>

//commande de compilation mingw simple
//g++ -std=c++17 pe_gen_window3.cpp -lkeystone -o pe_gen_window3.exe

using namespace std;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr u32 FILE_ALIGNMENT = 0x200;
constexpr u32 SECTION_ALIGNMENT = 0x1000;
constexpr u64 IMAGE_BASE = 0x4000000; //0x140000000ULL;

constexpr u32 IMAGE_SCN_CNT_CODE_ = 0x20000000;
constexpr u32 IMAGE_SCN_MEM_READ_ = 0x40000000;
constexpr u32 IMAGE_SCN_MEM_WRITE_ = 0x80000000;
constexpr u32 IMAGE_SCN_MEM_EXECUTE_ = 0x20000000;
constexpr u32 IMAGE_SCN_CNT_INITIALIZED_DATA_ = 0x40000000;

static inline u64 align_up(u64 v, u64 a) { return (v + a - 1) & ~(a - 1); }

//pout idata
struct ImportDescriptor {
    string dll_name;
    vector<string> functions;
    u32 ilt_offset = 0;
    u32 iat_offset = 0; //Adresses des dll dans l'IAT (pointeur des chargements virtuel en ajoutant image base ())
    u32 name_offset = 0;
    u32 descriptor_offset = 0;
    std::vector<u32> iat_func; // Adresses des fonctions dans l'IAT (non calculer par windows à cette emplacement)
};

// pour le PE Builder
struct Section {
    string name;
    vector<u8> content;
    u32 virtualAddress = 0;
    u32 virtualSize = 0;
    u32 sizeOfRawData = 0;
    u32 pointerToRawData = 0;
    u32 characteristics = 0;
};

class PEBuilder {
private:
    vector<Section> sections;
    vector<ImportDescriptor> imports;
    u32 entryRVA = 0;
    u32 importTableRVA = 0;
    u32 importTableSize = 0;
    struct DataDirectoryEntry {
        u32 rva = 0;
        u32 size = 0;
    };
    DataDirectoryEntry dataDirectories[16] = {};

    Section& add_section(const string& name, u32 characteristics) {
        sections.push_back({name, {0x90, 0x90, 0x90, 0x90}, 0, 4, 0, 0, characteristics}); //init avec valeur pour pouvoir layout tout le temps avec text non vide (type nop instruction)
        return sections.back();
    }

public:
    PEBuilder() {
        add_section(".text", 0x60000020); // CODE | EXECUTE | READ (emplacement du code à écrire par l'utilisateur)
    }

    Section& add_custom_section(const string& name, u32 characteristics) {
        return add_section(name, characteristics);
    }

    // Ajoute une section
    void push_section(const Section& section) {
        sections.push_back(section);
    }

    // Remplace une section par son index
    void replace_section(size_t index, const Section& new_section) {
        if (index < sections.size()) {
            sections[index] = new_section;
        }
    }

    void set_data_directory(u32 index, u32 rva, u32 size) {
        if (index < 16) {
            dataDirectories[index].rva = rva;
            dataDirectories[index].size = size;
        }
    }

    u32 get_data_rva(u32 sectionIndex, size_t offset) {
        if (sectionIndex < sections.size()) {
            return sections[sectionIndex].virtualAddress + (u32)offset;
        }
        return 0;
    }

    void layout() {
        u32 va = SECTION_ALIGNMENT;
        u32 fileptr = FILE_ALIGNMENT*2;
        for (auto& sec : sections) {
            sec.virtualAddress = align_up(va, SECTION_ALIGNMENT);
            sec.virtualSize = sec.content.size();//(u32)align_up(sec.content.size(), SECTION_ALIGNMENT);
            sec.sizeOfRawData = (u32)align_up(sec.content.size(), SECTION_ALIGNMENT);//pour l'instant match que avec SECTION_ALIGNEMENT du coup code big (sinon cff explorer ne peut pas lire le code mais en vrai on peut mettre FILE_ALIGNEMENT pour obtimisé taille de l'exe)
            sec.pointerToRawData = align_up(fileptr, FILE_ALIGNMENT);
            //va += (u32)align_up(sec.virtualSize ? sec.virtualSize : 1, SECTION_ALIGNMENT);
            va = align_up(sec.virtualAddress + sec.virtualSize, SECTION_ALIGNMENT);
            fileptr += sec.sizeOfRawData;
        }
    }

    void layout_not_used() {
        u32 va = SECTION_ALIGNMENT;       // Première section commence à 0x1000
        u32 fileptr = FILE_ALIGNMENT;     // Première section commence après les headers alignés

        for (auto& sec : sections) {

            sec.virtualAddress = va;

            // Taille réelle des données
            sec.virtualSize = sec.content.size();

            // Taille dans le fichier : alignée
            sec.sizeOfRawData = align_up(sec.content.size(), FILE_ALIGNMENT);

            // Offset dans le fichier
            sec.pointerToRawData = fileptr;

            // RVA de la section suivante: aligné
            va += align_up(sec.virtualSize, SECTION_ALIGNMENT);

            // offset du fichier suivant : aligné
            fileptr += sec.sizeOfRawData;
        }
    }

    vector<u8> build(u32 entry_rva) {
        entryRVA = entry_rva;
        layout();

        u32 sizeOfImage = 0;
        for (const auto& sec : sections) {
            sizeOfImage = max(sizeOfImage, sec.virtualAddress + (u32)align_up(sec.virtualSize, SECTION_ALIGNMENT));
        }

        vector<u8> hdr(IMAGE_BASE, 0);
        hdr[0] = 'M'; hdr[1] = 'Z';
        u32 e_lfanew = 0x80;
        *(u32*)&hdr[0x3C] = e_lfanew;

        size_t p = e_lfanew;
        hdr[p++] = 'P'; hdr[p++] = 'E'; hdr[p++] = 0; hdr[p++] = 0;

        auto push_u8 = [&](u8 v) { hdr[p++] = v; };
        auto push_u16 = [&](u16 v) {
            hdr[p++] = (u8)(v & 0xFF);
            hdr[p++] = (u8)(v >> 8);
        };
        auto push_u32 = [&](u32 v) {
            for (int i = 0; i < 4; ++i) hdr[p++] = (u8)((v >> (i * 8)) & 0xFF);
        };
        auto push_u64 = [&](u64 v) {
            for (int i = 0; i < 8; ++i) hdr[p++] = (u8)((v >> (i * 8)) & 0xFF);
        };

        push_u16(0x8664); // Machine (AMD64)
        push_u16((u16)sections.size()); // NumberOfSections
        u32 timestamp = (u32)std::chrono::system_clock::now().time_since_epoch().count();
        push_u32(timestamp); // TimeDateStamp
        push_u32(0); // PointerToSymbolTable
        push_u32(0); // NumberOfSymbols
        push_u16(0xF0); // SizeOfOptionalHeader
        push_u16(0x0022); // Characteristics

        push_u16(0x20B); // Magic
        push_u8(0x02);      // MajorLinkerVersion
        push_u8(0x1E);      // MinorLinkerVersion

        u32 sizeOfCode = 0;
        for (const auto& sec : sections) {
            if (sec.characteristics & 0x20000000) { // IMAGE_SCN_CNT_CODE
                sizeOfCode += sec.sizeOfRawData;
            }
        }
        push_u32(sizeOfCode);

        u32 sizeOfInitializedData = 0;
        for (const auto& sec : sections) {
            if (sec.characteristics & 0x40000000) { // IMAGE_SCN_CNT_INITIALIZED_DATA
                sizeOfInitializedData += sec.sizeOfRawData;
            }
        }
        push_u32(sizeOfInitializedData);

        push_u32(0); // SizeOfUninitializedData
        push_u32(entryRVA); // AddressOfEntryPoint
        push_u32(sections[0].virtualAddress); // BaseOfCode
        push_u64(IMAGE_BASE); // ImageBase
        push_u32(SECTION_ALIGNMENT);
        push_u32(FILE_ALIGNMENT);
        push_u16(6); push_u16(0); // OS version
        push_u16(0); push_u16(0); // Image version
        push_u16(6); push_u16(0); // Subsystem version
        push_u32(0); // Win32VersionValue
        push_u32(sizeOfImage);

        size_t off_sizeOfHeaders = p;
        push_u32(0); // Placeholder pour SizeOfHeaders
        push_u32(0); // CheckSum
        push_u16(3); // Subsystem (CONSOLE)
        push_u16(0); // DllCharacteristics
        push_u64(0x100000); push_u64(0x1000); // Stack
        push_u64(0x100000); push_u64(0x1000); // Heap
        push_u32(0); // LoaderFlags
        push_u32(16); // NumberOfRvaAndSizes

        for (int i = 0; i < 16; ++i) {
            push_u32(dataDirectories[i].rva);
            push_u32(dataDirectories[i].size);
        }

        for (const auto& sec : sections) {
            char name[8] = {0};
            strncpy(name, sec.name.c_str(), 8);
            for (int i = 0; i < 8; ++i) push_u8(name[i]);
            push_u32(sec.virtualSize);
            push_u32(sec.virtualAddress);
            push_u32(sec.sizeOfRawData);
            push_u32(sec.pointerToRawData);
            push_u32(0); push_u32(0); // Relocs/Linenumbers
            push_u16(0); push_u16(0);
            push_u32(sec.characteristics);
        }

        u32 realSizeOfHeaders = (u32)align_up(p, FILE_ALIGNMENT);
        for (int i = 0; i < 4; ++i) hdr[off_sizeOfHeaders + i] = (u8)((realSizeOfHeaders >> (i * 8)) & 0xFF);

        u32 file_end = realSizeOfHeaders;
        for (const auto& sec : sections) {
            file_end = max(file_end, sec.pointerToRawData + sec.sizeOfRawData);
        }

        vector<u8> file(file_end, 0);
        memcpy(file.data(), hdr.data(), p);

        for (const auto& sec : sections) {
            if (!sec.content.empty()) {
                // Copie le contenu réel de la section
                memcpy(&file[sec.pointerToRawData], sec.content.data(), sec.content.size());

                // Si la taille brute est supérieure au contenu, remplir avec des NOP (0x90) pour .text
                if (sec.sizeOfRawData > sec.content.size()) {
                    u8 fill_byte = (sec.characteristics & 0x20000000) ? 0x90 : 0x00;
                    // 0x20000000 = IMAGE_SCN_CNT_CODE (section de code)
                    memset(
                        &file[sec.pointerToRawData + sec.content.size()],
                        fill_byte,
                        sec.sizeOfRawData - sec.content.size()
                    );
                }
            } else {
                // Si la section est vide mais a une taille brute (ex: .text vide)
                if (sec.sizeOfRawData > 0) {
                    u8 fill_byte = (sec.characteristics & 0x20000000) ? 0x90 : 0x00;
                    memset(
                        &file[sec.pointerToRawData],
                        fill_byte,
                        sec.sizeOfRawData
                    );
                }
            }
        }

        return file;
    }

    Section& get_section(size_t index) { return sections[index]; }
    Section& text() { return sections[0]; }
    //Section& idata() { return sections[1]; }

    void see_section(){
        for (size_t i = 0; i < sections.size(); ++i) {
        std::cout << "Section " << i << ": " << sections[i].name
              << ", VirtualAddress: 0x" << std::hex << sections[i].virtualAddress
              << ", VirtualSize: 0x" << sections[i].virtualSize << std::endl;
        }
    }

};

class IDATA {
private:
    std::vector<u8> content;
    std::vector<ImportDescriptor> imports;

    void push_u8(u8 v) { content.push_back(v); }
    void push_u16(u16 v) {
        push_u8((u8)(v & 0xFF));
        push_u8((u8)(v >> 8));
    }
    void push_u32(u32 v) {
        for (int i = 0; i < 4; ++i) push_u8((u8)((v >> (i * 8)) & 0xFF));
    }

    void push_u64(u64 v) {
        for (int i = 0; i < 8; ++i) push_u8((u8)((v >> (i * 8)) & 0xFF));
    }

    // Aligne content à 2 octets (pair) ou 1 octet (impair) selon besoin
    void align_to_even(bool force_even = true) {
        if (force_even && (content.size() % 2 != 0)) push_u8(0);
        else if (!force_even && (content.size() % 2 == 0)) push_u8(0);
    }

    u32 calculate_hint_name_entry_size(const std::string& func) {
        u32 size = 2; // Hint (2 octets)
        size += (u32)func.size() + 1; // Nom de la fonction (ASCIIZ)
        if ((func.size() + 1) % 2 != 0) size += 1; // Padding
        return size;
    }

public:
    void add_import(const std::string& dll_name, const std::vector<std::string>& functions) {
        imports.push_back({dll_name, functions});
    }

    void prepare() {
        content.clear();

        // 1. Calcule la taille de la Import Directory Table
        u32 import_directory_table_size = (u32)imports.size() * 0x14 + 0x14;

        // 2. Calcule la taille des ILT et IAT pour chaque DLL
        std::vector<u32> ilt_sizes;
        std::vector<u32> iat_sizes;
        for (const auto& imp : imports) {
            ilt_sizes.push_back((u32)(imp.functions.size() + 1) * 8);
            iat_sizes.push_back((u32)(imp.functions.size() + 1) * 8);
        }

        // 3. Calcule la taille des noms de DLL
        u32 dll_names_size = 0;
        for (const auto& imp : imports) {
            dll_names_size += (u32)imp.dll_name.size() + 1;
        }

        // 4. Calcule la taille de la Hint/Name Table
        u32 hint_name_table_size = 0;
        for (const auto& imp : imports) {
            for (const auto& func : imp.functions) {
                hint_name_table_size += calculate_hint_name_entry_size(func);
            }
        }

        // 5. Calcule les offsets de chaque partie
        u32 ilt_offset = import_directory_table_size;
        u32 iat_offset = ilt_offset;
        for (u32 ilt_size : ilt_sizes) iat_offset += ilt_size;

        u32 dll_names_offset = iat_offset;
        for (u32 iat_size : iat_sizes) dll_names_offset += iat_size;

        u32 hint_name_table_offset = dll_names_offset + dll_names_size;

        // 6. Met à jour les offsets dans les descripteurs d'import
        u32 current_ilt_offset = ilt_offset;
        u32 current_iat_offset = iat_offset;
        u32 current_dll_name_offset = dll_names_offset;
        u32 current_import_directory_offset = 0;

        for (auto& imp : imports) {
            imp.descriptor_offset = current_import_directory_offset;
            imp.ilt_offset = current_ilt_offset;
            imp.iat_offset = current_iat_offset;
            imp.name_offset = current_dll_name_offset;

            current_ilt_offset += ilt_sizes[current_import_directory_offset / 0x14];
            current_iat_offset += iat_sizes[current_import_directory_offset / 0x14];
            current_dll_name_offset += (u32)imp.dll_name.size() + 1;
            current_import_directory_offset += 0x14;
        }

        // 7. Écrit la Import Directory Table
        for (const auto& imp : imports) {
            push_u32(imp.ilt_offset);
            push_u32(0);
            push_u32(0);
            push_u32(imp.name_offset);
            push_u32(imp.iat_offset); //ici addresse de début des pointeurs virtuels des fonctions de windows (Pour la récupérer ajouter image_base qui pointera sur la première fonction importer de la dll)
        }

        // Terminaison de la table des descripteurs
        push_u32(0); push_u32(0); push_u32(0); push_u32(0); push_u32(0);

        // 8. Écrit les ILT
        for (const auto& imp : imports) {
            for (size_t i = 0; i < imp.functions.size(); ++i) {
                push_u64(0); // Placeholder
            }
            push_u64(0); // Terminaison
        }

        // 9. Écrit les IAT
        for (const auto& imp : imports) {
            for (size_t i = 0; i < imp.functions.size(); ++i) {
                push_u64(0); // Sera rempli par le chargeur
            }
            push_u64(0); // Terminaison
        }

        // 10. Écrit les noms de DLL
        for (const auto& imp : imports) {
            for (char c : imp.dll_name) push_u8(c);
            push_u8(0);
        }

        // 11. Écrit la Hint/Name Table
        for (const auto& imp : imports) {
            for (const auto& func : imp.functions) {
                push_u16(0); // Hint
                for (char c : func) push_u8(c);
                push_u8(0);
                align_to_even();
            }
        }
    }

    void reprepare(u32 idata_rva) {
    size_t content_size = content.size();
    content.clear();

    // 1. Calcule les offsets de chaque partie
    u32 import_directory_table_size = (u32)imports.size() * 0x14 + 0x14;
    std::vector<u32> ilt_sizes;
    std::vector<u32> iat_sizes;
    for (const auto& imp : imports) {
        ilt_sizes.push_back((u32)(imp.functions.size() + 1) * 8); // 8 octets pour chaque entrée 64 bits
        iat_sizes.push_back((u32)(imp.functions.size() + 1) * 8); // 8 octets pour chaque entrée 64 bits
    }

    u32 dll_names_size = 0;
    for (const auto& imp : imports) {
        dll_names_size += (u32)imp.dll_name.size() + 1;
    }

    u32 hint_name_table_size = 0;
    for (const auto& imp : imports) {
        for (const auto& func : imp.functions) {
            hint_name_table_size += calculate_hint_name_entry_size(func);
        }
    }

    u32 ilt_offset = import_directory_table_size;
    u32 iat_offset = ilt_offset;
    for (u32 ilt_size : ilt_sizes) iat_offset += ilt_size;

    u32 dll_names_offset = iat_offset;
    for (u32 iat_size : iat_sizes) dll_names_offset += iat_size;

    u32 hint_name_table_offset = dll_names_offset + dll_names_size;

    // 2. Écrit la Import Directory Table avec les RVA absolus
    u32 current_ilt_offset = ilt_offset;
    u32 current_iat_offset = iat_offset;
    u32 current_dll_name_offset = dll_names_offset;

    for (auto& imp : imports) {
        imp.iat_offset = current_iat_offset;
        push_u32(idata_rva + current_ilt_offset);
        push_u32(0);
        push_u32(0);
        push_u32(idata_rva + current_dll_name_offset);
        push_u32(idata_rva + current_iat_offset);

        current_ilt_offset += ilt_sizes[&imp - &imports[0]];
        current_iat_offset += iat_sizes[&imp - &imports[0]];
        current_dll_name_offset += (u32)imp.dll_name.size() + 1;
    }

    // Terminaison de la table des descripteurs
    push_u32(0); push_u32(0); push_u32(0); push_u32(0); push_u32(0);

    // 3. Écrit les ILT avec les RVA absolus
    u64 current_hint_name_rva = static_cast<u64>(idata_rva) + hint_name_table_offset;
    for (const auto& imp : imports) {
        for (const auto& func : imp.functions) {
            push_u32(static_cast<u32>(current_hint_name_rva));
            push_u32(0);
            current_hint_name_rva += calculate_hint_name_entry_size(func);
        }
        push_u64(0); // Terminaison
    }

    // 4. Écrit les IAT avec les adresses des fonctions (comme ILT)
    current_hint_name_rva = static_cast<u64>(idata_rva) + hint_name_table_offset;
    for (auto& imp : imports) {
        imp.iat_func.clear();
        for (const auto& func : imp.functions){
            u64 rva_name = current_hint_name_rva;
            imp.iat_func.push_back(static_cast<u32>(rva_name));      // stocké pour ton asm

            push_u32(static_cast<u32>(rva_name));
            push_u32(0);                         // IAT = RVA du Hint/Name
            current_hint_name_rva += calculate_hint_name_entry_size(func);
        }
        push_u64(0);
    }

    // 5. Écrit les noms de DLL
    for (const auto& imp : imports) {
        for (char c : imp.dll_name) push_u8(c);
        push_u8(0);
    }

    bool is_pair_function=true;
    if (content.size() % 2 != 0) is_pair_function=false;

    // 6. Écrit la Hint/Name Table
    for (const auto& imp : imports) {
        for (const auto& func : imp.functions) {
            push_u16(0); // Hint
            for (char c : func) push_u8(c);
            push_u8(0);
            align_to_even(is_pair_function); //aligner en fonction du début si pair ou impaire
        }
    }
}
    //fonction qui renvoie la position des adresses virtuelles chargé par windows (ajouter IMAGE_BASE dans le code assembleur pour les trouvé)
    u32 get_import_rva(const std::string& dll_name, const std::string& func_name, u32 idata_rva) {
        u32 current_iat_offset = idata_rva + 0x14 * (u32)imports.size() + 0x14;
        for (const auto& imp : imports) {
            if (imp.dll_name == dll_name) {
                for (size_t i = 0; i < imp.functions.size(); ++i) {
                    if (imp.functions[i] == func_name) {
                        return imp.iat_offset + idata_rva + i * 8;
                    }
                }
            }
            current_iat_offset += (u32)(imp.functions.size() + 1) * 8;
        }
        return 0; // Fonction non trouvée
    }

    //inutile car on prend directement avec rva pour les adresses calculés
    u64 get_import_va(const std::string& dll_name, const std::string& func_name, u64 image_base) {
        for (const auto& imp : imports) {
            if (imp.dll_name == dll_name) {
                for (size_t i = 0; i < imp.functions.size(); ++i) {
                    if (imp.functions[i] == func_name) {
                        // imp.iat_func[i] est un RVA 32 bits, on le combine avec l'ImageBase 64 bits
                        return image_base + static_cast<u64>(imp.iat_func[i]);
                    }
                }
            }
        }
        return 0; // Fonction non trouvée
    }

    std::vector<u8> get_content() const { return content; }
    u32 get_size() const { return static_cast<u32>(content.size()); }
};

struct ICONDIR {
    u16 reserved;
    u16 type;
    u16 count;
};
struct ICONDIRENTRY {
    u8  width;
    u8  height;
    u8  colorCount;
    u8  reserved;
    u16 planes;
    u16 bitCount;
    u32 bytesInRes;
    u32 imageOffset;
};

class RSRC {
public:
    std::vector<u8> content;

    enum {
        RT_CURSOR_        = 1,
        RT_BITMAP_        = 2,
        RT_ICON_          = 3,
        RT_MENU_          = 4,
        RT_DIALOG_        = 5,
        RT_STRING_        = 6,
        RT_FONTDIR_       = 7,
        RT_FONT_          = 8,
        RT_ACCELERATOR_   = 9,
        RT_RCDATA_        = 10,
        RT_MESSAGETABLE_  = 11,
        RT_GROUP_CURSOR_  = 12,
        RT_GROUP_ICON_    = 14,
        RT_VERSION_       = 16,
        RT_MANIFEST_      = 24,
    };

    struct Item {
        u32 type;
        u32 id;
        u16 lang;
        std::vector<u8> data;
    };

    std::vector<Item> items;

    // read file
    static std::vector<u8> load_file(const std::string& path){
        std::ifstream f(path, std::ios::binary);
        if(!f) throw std::runtime_error("open failed: " + path);
        return std::vector<u8>(std::istreambuf_iterator<char>(f), {});
    }

    // -------------------------------------------------------
    // Add raw resource
    // -------------------------------------------------------
    void add_resource(u32 type, u32 id, const std::vector<u8>& data, u16 lang=0x0409){
        items.push_back({type,id,lang,data});
    }

    // -------------------------------------------------------
    // Add icon from .ico file (builds RT_ICON + RT_GROUP_ICON)
    // -------------------------------------------------------
    void add_icon_from_file(const std::string& icoPath){
        auto ico = load_file(icoPath);
        if (ico.size() < sizeof(ICONDIR)) throw std::runtime_error("bad ico");
        ICONDIR hdr;
        memcpy(&hdr, ico.data(), sizeof(ICONDIR));

        if (hdr.type != 1) throw std::runtime_error("not icon");

        auto entries = reinterpret_cast<const ICONDIRENTRY*>(ico.data()+sizeof(ICONDIR));
        if (ico.size() < sizeof(ICONDIR) + hdr.count*sizeof(ICONDIRENTRY))
            throw std::runtime_error("ico truncated");

        // Group icon directory
        std::vector<u8> grp;
        auto push16=[&](u16 v){ grp.push_back(v&0xFF); grp.push_back(v>>8); };
        auto push32=[&](u32 v){ grp.push_back(v&0xFF); grp.push_back((v>>8)&0xFF); grp.push_back((v>>16)&0xFF); grp.push_back((v>>24)&0xFF); };

        push16(0); // reserved
        push16(1); // type
        push16(hdr.count);

        for (int i=0;i<hdr.count;i++){
            const ICONDIRENTRY &e = entries[i];

            if (ico.size() < e.imageOffset + e.bytesInRes)
                throw std::runtime_error("ico img truncated");

            std::vector<u8> img(ico.begin()+e.imageOffset,
                                ico.begin()+e.imageOffset+e.bytesInRes);

            u16 iconId = i+1;

            add_resource(RT_ICON_, iconId, img);

            // GRPICONENTRY
            grp.push_back(e.width);
            grp.push_back(e.height);
            grp.push_back(e.colorCount);
            grp.push_back(0);
            push16(e.planes);
            push16(e.bitCount);
            push32(e.bytesInRes);
            push16(iconId);
        }

        add_resource(RT_GROUP_ICON_, 1, grp);
    }

    // -------------------------------------------------------
    // Add VERSIONINFO (full Windows structure)
    // -------------------------------------------------------
    static void push_u16_vec(std::vector<u8>& out, u16 v){
        out.push_back(v&0xFF); out.push_back(v>>8);
    }
    static void push_u32_vec(std::vector<u8>& out, u32 v){
        out.push_back(v&0xFF); out.push_back((v>>8)&0xFF);
        out.push_back((v>>16)&0xFF); out.push_back((v>>24)&0xFF);
    }

    static void push_wstr(std::vector<u8>& out, const std::wstring& w){
        for (wchar_t c : w){
            push_u16_vec(out, (u16)c);
        }
        push_u16_vec(out, 0);
    }

    static void align4(std::vector<u8>& out){
        while(out.size() % 4) out.push_back(0);
    }

   std::vector<u8> build_version_resource(
    const std::wstring& fileVersion,
    const std::wstring& productVersion,
    const std::wstring& companyName,
    const std::wstring& fileDescription,
    const std::wstring& productName,
    const std::wstring& originalFilename,
    const std::wstring& legalCopyright)
{
    std::vector<u8> v;

    auto push_u16 = [&](u16 val){ v.push_back(val & 0xFF); v.push_back(val >> 8); };
    auto push_u32 = [&](u32 val){ for(int i=0;i<4;i++) v.push_back((val >> (8*i)) & 0xFF); };
    auto push_wstr = [&](const std::wstring& s){ for(wchar_t c : s) push_u16(c); push_u16(0); };
    auto align4 = [&](){ while(v.size() % 4) v.push_back(0); };

    auto begin_block = [&](bool type_strings = true){
        size_t pos = v.size();
        push_u16(0); // wLength
        push_u16(0); // wValueLength
        push_u16(type_strings ? 1 : 0); // wType
        return pos;
    };
    auto end_block = [&](size_t pos, u16 wValueLength){
        u16 wTotal = (u16)(v.size() - pos);
        v[pos] = wTotal & 0xFF;
        v[pos+1] = wTotal >> 8;
        v[pos+2] = wValueLength & 0xFF;
        v[pos+3] = wValueLength >> 8;
    };

    // -------------------------
    // VS_VERSION_INFO root
    // -------------------------
    size_t root = begin_block(false); //pas du text le premier
    push_wstr(L"VS_VERSION_INFO");
    align4();

    // VS_FIXEDFILEINFO (52 bytes)
    const size_t vsFixedOffset = v.size();
    push_u32(0xFEEF04BD); // dwSignature
    push_u32(0x00010000); // dwStrucVersion
    push_u32(0);          // dwFileVersionMS
    push_u32(0);          // dwFileVersionLS
    push_u32(0);          // dwProductVersionMS
    push_u32(0);          // dwProductVersionLS
    push_u32(0x3F000000); // dwFileFlagsMask  <-- correct
    push_u32(0);          // dwFileFlags
    push_u32(0x00000004); // dwFileOS        <-- correct
    push_u32(1);          // dwFileType
    push_u32(0);          // dwFileSubtype
    push_u32(0);          // dwFileDateMS
    push_u32(0);          // dwFileDateLS
    align4();

    // -------------------------
    // VarFileInfo
    // -------------------------
    size_t vfi = begin_block();
    push_wstr(L"VarFileInfo");
    align4();

    size_t var = begin_block(false);
    push_wstr(L"Translation");
    align4();
    push_u16(0x0409); // LangID
    push_u16(0x04E4); // CodePage
    align4();
    end_block(var, 4);
    end_block(vfi, 0);

    // -------------------------
    // StringFileInfo
    // -------------------------
    size_t sfi = begin_block();
    push_wstr(L"StringFileInfo");
    align4();

    size_t str0409 = begin_block();
    push_wstr(L"040904E4");
    align4();

    auto add_string = [&](const wchar_t* key, const std::wstring& value, u16 wValueLen = 0){
        size_t b = begin_block();
        push_wstr(key);
        align4();
        for(wchar_t c: value) push_u16(c);
        push_u16(0);
        align4();
        end_block(b, wValueLen);
    };

    add_string(L"FileDescription", fileDescription, (u16)(fileDescription.length()+1));
    add_string(L"FileVersion", fileVersion,(u16)(fileVersion.length()+1));
    add_string(L"InternalName", originalFilename,(u16)(originalFilename.length()+1));
    add_string(L"LegalCopyright", legalCopyright,(u16)(legalCopyright.length()+1));
    add_string(L"OriginalFilename", originalFilename,(u16)(originalFilename.length()+1));
    add_string(L"ProductVersion", productVersion,(u16)(productVersion.length()+1));
    add_string(L"AssemblyVersion", fileVersion,(u16)(fileVersion.length()+1));
    add_string(L"ProductName", productName,(u16)(productName.length()+1));

    end_block(str0409, 0);
    end_block(sfi, 0);

    // -------------------------
    // finalize root
    // -------------------------
    end_block(root, 52); // VS_FIXEDFILEINFO

    return v;
}

    void add_version_full(
        const std::wstring& fileVersion,
        const std::wstring& productVersion,
        const std::wstring& companyName,
        const std::wstring& fileDescription,
        const std::wstring& productName,
        const std::wstring& originalFilename,
        const std::wstring& copyright)
    {
        auto v = build_version_resource(
            fileVersion,
            productVersion,
            companyName,
            fileDescription,
            productName,
            originalFilename,
            copyright
        );

        add_resource(RT_VERSION_, 1, v);
    }

    // -------------------------------------------------------
    //
    // -------------------------------------------------------

    void add_manifest(
    const std::string& exeName,
    const std::string& version = "1.0.0.0",
    bool dpiAware = true,
    bool perMonitorV2 = true,
    bool requireAdmin = false,
    bool commonControlsV6 = false
    )
{
    std::string level = requireAdmin ? "requireAdministrator" : "asInvoker";

    std::string xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
        "  <assemblyIdentity\n"
        "      version=\"" + version + "\"\n"
        "      processorArchitecture=\"amd64\"\n"
        "      name=\"" + exeName + "\"\n"
        "      type=\"win32\"/>\n"
        "\n"
        "  <description>" + exeName + "</description>\n"
        "\n";

    if (commonControlsV6)
    {
    xml +=
        "  <dependency>\n"
        "    <dependentAssembly>\n"
        "      <assemblyIdentity\n"
        "        type=\"win32\"\n"
        "        name=\"Microsoft.Windows.Common-Controls\"\n"
        "        version=\"6.0.0.0\"\n"
        "        processorArchitecture=\"*\"\n"
        "        publicKeyToken=\"6595b64144ccf1df\"\n"
        "        language=\"*\"/>\n"
        "    </dependentAssembly>\n"
        "  </dependency>\n\n";
    }

     xml +=
        "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
        "    <security>\n"
        "      <requestedPrivileges>\n"
        "        <requestedExecutionLevel level=\"" + level + "\" uiAccess=\"false\"/>\n"
        "      </requestedPrivileges>\n"
        "    </security>\n"
        "  </trustInfo>\n"
        "\n"
        "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n"
        "    <windowsSettings>\n";

    if (dpiAware)
        xml += "      <dpiAware>true</dpiAware>\n";

    if (perMonitorV2)
        xml += "      <dpiAwareness>PerMonitorV2</dpiAwareness>\n";

    xml +=
        "    </windowsSettings>\n"
        "  </application>\n"
        "</assembly>\n";

    std::vector<u8> data(xml.begin(), xml.end());

    // RT_MANIFEST = 24, ID = 1
    add_resource(RT_MANIFEST_, 1, data);
}

//pour add dialog creer label, edit et boutton
struct DialogControl {
    enum class Type { BUTTON, DEFBUTTON, LABEL, EDIT, FILLRECT, FRAMERECT, DRAWRECT } type;
    bool enabled;
    u16  id;          // utile pour BUTTON et EDIT
    std::wstring text;
    u16 x, y, width, height;
};

//structure des element dialog
struct DialogDesc {
    u32 id = 1;
    std::wstring title = L"DIALOG BOX";
    bool italic = false;
    u16 size_point = 8;
    u16 weight = 0;
    u16 x = 0, y = 0;
    u16 width = 200, height = 100;
    u8 character_set = 1; //jeu de charactère
    std::wstring font = L"MS Shell Dlg"; //police de charactère
    std::vector<DialogControl> controls; // tous les boutons et labels
};


void add_dialog(const DialogDesc& dsc, u16 lang = 0x0409)
{
    std::vector<u8> r;

    auto push_u8 = [&](u8 v) { r.push_back(v); };
    auto push_u16 = [&](u16 v){ r.push_back(v&0xFF); r.push_back(v>>8); };
    auto push_u32 = [&](u32 v){ for(int i=0;i<4;i++) r.push_back((v>>(8*i))&0xFF); };
    auto push_wstr = [&](const std::wstring& s){ for(wchar_t c : s) push_u16(c); push_u16(0); };
    auto align4 = [&](){ while(r.size() % 4) r.push_back(0); };
    auto align2 = [&](){ while(r.size() % 2) r.push_back(0); };

    // -------------------------------------------------
    // DIALOGEX header
    // -------------------------------------------------
    push_u16(1); push_u16(0xFFFF);              // DIALOGEX signature
    push_u32(0);                           // help ID

    push_u32(0);                           // exStyle
    push_u32(
        WS_POPUP |
        WS_CAPTION | WS_SYSMENU |
        DS_MODALFRAME | DS_SETFONT
    ); //style


    push_u16(static_cast<u16>(dsc.controls.size())); //cDlgItems (nombre de controle boite de dialog)

    push_u16(dsc.x);
    push_u16(dsc.y);
    push_u16(dsc.width);
    push_u16(dsc.height);

    push_u16(0); // menu
    align2();
    push_u16(0); // class
    push_wstr(dsc.title);
    align2();


    push_u16(dsc.size_point); //taille de points (que si DS_SETFONT ou DS_SHELLFONT)
    push_u16(dsc.weight); //poids (que si DS_SETFONT ou DS_SHELLFONT)
    if (dsc.italic) push_u8(1); //italique true ou false (que si DS_SETFONT ou DS_SHELLFONT)
    else push_u8(0);
    push_u8(dsc.character_set); //charset Le jeu de caractères à utiliser (que si DS_SETFONT ou DS_SHELLFONT)

    push_wstr(dsc.font); //Police de caractères nom (que si DS_SETFONT ou DS_SHELLFONT)
    align2();

    align4();

    // -------------------
    // Controls
    // -------------------
    for (const auto& ctrl : dsc.controls)
    {
        if (!ctrl.enabled) continue;

        push_u32(0);           // helpID
        push_u32(0);           // exStyle

        u32 style = WS_CHILD | WS_VISIBLE;
        if(ctrl.type == DialogControl::Type::BUTTON)
            style |= WS_TABSTOP | BS_PUSHBUTTON;
        else if(ctrl.type == DialogControl::Type::DEFBUTTON)
            style |= WS_TABSTOP | BS_PUSHBUTTON | BS_DEFPUSHBUTTON;
        else if(ctrl.type == DialogControl::Type::LABEL)
            style |= SS_LEFT;
        else if(ctrl.type == DialogControl::Type::EDIT)
            style |= WS_TABSTOP | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL;
        else if(ctrl.type == DialogControl::Type::FILLRECT)
            style |= SS_BLACKRECT;
        else if(ctrl.type == DialogControl::Type::FRAMERECT)
            style |= SS_BLACKFRAME;
        else if(ctrl.type == DialogControl::Type::DRAWRECT)
            style |= SS_OWNERDRAW;

        push_u32(style);

        push_u16(ctrl.x);
        push_u16(ctrl.y);
        push_u16(ctrl.width);
        push_u16(ctrl.height);

        push_u32(ctrl.id); // utile pour button et le edit, inutile pour label mais on peut mettre 0
        if(ctrl.type == DialogControl::Type::BUTTON || ctrl.type == DialogControl::Type::DEFBUTTON)
        {
            push_u16(0xFFFF); push_u16(0x0080); // BUTTON class
        }
        else if(ctrl.type == DialogControl::Type::LABEL || ctrl.type == DialogControl::Type::FRAMERECT || ctrl.type == DialogControl::Type::FILLRECT || ctrl.type == DialogControl::Type::DRAWRECT)
        {
            push_u16(0xFFFF); push_u16(0x0082); // STATIC class
        }
        else if(ctrl.type == DialogControl::Type::EDIT)
        {
            push_u16(0xFFFF); push_u16(0x0081); // EDIT class
        }

        push_wstr(ctrl.text);
        align2();
        push_u16(0); // extra count
        align4();
    }

    // -------------------------------------------------
    // push resource
    // -------------------------------------------------
    add_resource(RT_DIALOG_, dsc.id, r, lang);
}

    // -------------------------------------------------------
    // BUILD RSRC SECTION (3-level directory)
    // -------------------------------------------------------
    void build(u32 rsrc_virtual_address)
{
    content.clear();

    // tri
    std::sort(items.begin(), items.end(), [](auto&a,auto&b){
        if(a.type!=b.type) return a.type<b.type;
        if(a.id!=b.id)     return a.id<b.id;
        return a.lang<b.lang;
    });

    struct Patch{ size_t where; u32 value; bool is_dir; };
    std::vector<Patch> patches;

    auto push_u16 = [&](u16 v){ content.push_back((u8)(v & 0xFF)); content.push_back((u8)(v >> 8)); };
    auto push_u32 = [&](u32 v){ for(int i=0;i<4;i++) content.push_back((u8)((v >> (8*i)) & 0xFF)); };
    auto align4 = [&](){ while(content.size() % 4) content.push_back(0); };

    // group by type -> id -> lang
    struct ItemRef { u32 type; u32 id; u16 lang; std::vector<u8>* data; };
    std::map<u32, std::map<u32, std::vector<Item>>> grouped;
    for (auto &it : items) grouped[it.type][it.id].push_back(it);

    // --- Root directory placeholder (16 bytes) ---
    size_t root_dir_pos = content.size();
    for(int i=0;i<16;i++) content.push_back(0);

    // reserve root entries (one per type)
    size_t root_entries_pos = content.size();
    size_t nTypes = grouped.size();
    for(size_t i=0;i<nTypes;i++) for(int j=0;j<8;j++) content.push_back(0);

    // iterate types
    size_t typeIndex = 0;
    for (auto &typePair : grouped) {
        u32 type = typePair.first;
        auto &idsMap = typePair.second;

        size_t root_entry_off = root_entries_pos + typeIndex * 8;
        // Name field: ID with high bit (we use numeric type -> so set high bit)
        *(u32*)(&content[root_entry_off]) = (u32)(type); //| 0x80000000u
        // OffsetToData placeholder -> patch later to point to type directory (RVA | 0x80000000)
        patches.push_back({ root_entry_off + 4, 0u, true });

        // --- write type directory ---
        size_t type_dir_raw = content.size();
        for(int i=0;i<16;i++) content.push_back(0); // IMAGE_RESOURCE_DIRECTORY

        // NumberOfIdEntries = idsMap.size()
        u16 idCount = (u16)idsMap.size();
        content[type_dir_raw + 14] = (u8)(idCount & 0xFF);
        content[type_dir_raw + 15] = (u8)((idCount >> 8) & 0xFF);

        // reserve id entries
        size_t id_entries_pos = content.size();
        for(size_t i=0;i<idCount;i++) for(int j=0;j<8;j++) content.push_back(0);

        // patch parent root entry -> RVA of type_dir
        patches.back().value = (u32)type_dir_raw;

        // iterate ids
        size_t idIdx = 0;
        for (auto &idPair : idsMap) {
            u32 id = idPair.first;
            auto &vecItems = idPair.second; // vector<Item>

            size_t id_entry_off = id_entries_pos + idIdx * 8;
            *(u32*)(&content[id_entry_off]) = (u32)(id); //| 0x80000000u
            patches.push_back({ id_entry_off + 4, 0u, true });

            // id dir
            size_t id_dir_raw = content.size();
            for(int i=0;i<16;i++) content.push_back(0);
            u16 langCount = (u16)vecItems.size();
            content[id_dir_raw + 14] = (u8)(langCount & 0xFF);
            content[id_dir_raw + 15] = (u8)((langCount >> 8) & 0xFF);

            // reserve lang entries
            size_t lang_entries_pos = content.size();
            for(size_t li=0; li<langCount; ++li) for(int j=0;j<8;j++) content.push_back(0);

            // patch id entry -> RVA of id_dir
            patches.back().value = (u32)id_dir_raw;

            // for each language -> data entry + raw data
            for(size_t li=0; li<vecItems.size(); ++li) {
                Item &it = vecItems[li];
                size_t lang_entry_off = lang_entries_pos + li*8;
                // Name = language id (no high bit)
                *(u32*)(&content[lang_entry_off]) = (u32)it.lang;

                // placeholder -> will point to IMAGE_RESOURCE_DATA_ENTRY (RVA)
                patches.push_back({ lang_entry_off + 4, 0u, false });

                // Reserve IMAGE_RESOURCE_DATA_ENTRY (16 bytes) at current raw
                size_t data_entry_raw = content.size();
                for(int b=0;b<16;b++) content.push_back(0);

                // raw data placed after data entry
                align4(); // ensure alignment before raw
                size_t raw_data_pos = content.size();
                content.insert(content.end(), it.data.begin(), it.data.end());
                align4();

                // IMPORTANT: write IMAGE_RESOURCE_DATA_ENTRY fields as RVAs (not raw offsets)
                // OffsetToData (DWORD) = rsrc_virtual_address + raw_data_pos
                u32 offsetToDataRVA = rsrc_virtual_address + (u32)raw_data_pos;
                *(u32*)(&content[data_entry_raw + 0]) = offsetToDataRVA;
                // Size
                *(u32*)(&content[data_entry_raw + 4]) = (u32)it.data.size();
                // CodePage & Reserved remain zero

                // patch lang entry -> RVA of data_entry (no high bit)
                patches.back().value = (u32)data_entry_raw;
            }

            ++idIdx;
        }

        ++typeIndex;
    }

    // fill root header: NumberOfIdEntries = nTypes
    u16 typesCountLE = (u16)nTypes;
    content[root_dir_pos + 14] = (u8)(typesCountLE & 0xFF);
    content[root_dir_pos + 15] = (u8)((typesCountLE >> 8) & 0xFF);

    // Now apply patches: each patch.value is a raw offset inside content -> write RVA (rsrc_virtual_address + raw)
    for (auto &p : patches) {
        u32 rva = (u32)(p.value);
        if (p.is_dir) rva |= 0x80000000u;
        //else rva += rsrc_virtual_address;
        *(u32*)(&content[p.where + 0]) = rva;
    }
}
};

//AMD64 tableau d'exception vers xdata (inutile, utilise addvectorexceptionhandler plus simple)
class PDATA {
public:
    std::vector<u8> content;

    void add_function(u32 beginRva, u32 endRva, u32 xdataRva)
    {
        auto push_u32 = [&](u32 v) {
            content.push_back(v & 0xFF);
            content.push_back((v >> 8) & 0xFF);
            content.push_back((v >> 16) & 0xFF);
            content.push_back((v >> 24) & 0xFF);
        };

        push_u32(beginRva);
        push_u32(endRva);
        push_u32(xdataRva);
    }

    u32 get_size() const { return static_cast<u32>(content.size()); }
};

//système inutile car l'exception est plus simple à gérer avec un handler avec addvectorexceptionhandler
class XDATA {
public:
    struct XDATA_Block {
    int id;        // identifiant unique
    u32 rva;       // position dans la section XDATA
    u32 handlerRva; // RVA du handler SEH
    };

    std::vector<u8> content;           // section binaire
    std::vector<XDATA_Block> blocks;   // liste des blocs

    // Ajouter un bloc UNWIND_INFO avec pile de départ rsp ajouter à une certaine valeur = stackSize
    void add_block(int id, u32 sehHandlerRva, u32 stackSize, u8 unwindFlags=0x0) {
        auto push_u8  = [&](u8 v){ content.push_back(v); };
        auto push_u16 = [&](u16 v){
            content.push_back(v & 0xFF);
            content.push_back(v >> 8);
        };
        auto push_u32 = [&](u32 v){
            content.push_back(v & 0xFF);
            content.push_back((v >> 8) & 0xFF);
            content.push_back((v >> 16) & 0xFF);
            content.push_back((v >> 24) & 0xFF);
        };

        u32 rva = static_cast<u32>(content.size()); // position dans la section

        bool hasStack = (stackSize != 0);
        u8 codeCount = 0;

        // Calcul du nombre de UNWIND_CODE
        if (hasStack)
        {
            if (stackSize <= 128)
                codeCount = 1;
            else if (stackSize <= 0xFFFF * 8)
                codeCount = 2;
            else
                codeCount = 3;
        }

        // UNWIND_INFO header
        push_u8((1 & 0x7) | ((unwindFlags & 0x1F) << 3)); // Version | Flags = EHANDLER=1 ou null=0  (:3 | :5)
        push_u8(hasStack ? 4 : 0);      // SizeOfProlog (variable si pile modifie ou non)
        push_u8(codeCount);             // CountOfCodes
        push_u8(0);                     // FrameRegister | Offset (:4)

        // ---- UNWIND_CODE ----
        if (hasStack)
        {
        if (stackSize <= 128)
            {
            // UWOP_ALLOC_SMALL
            u8 op   = 2;
            u8 info = (stackSize - 8) / 8;

            push_u8(4);                      // CodeOffset
            push_u8((info << 4) | op);
            }
        else if (stackSize <= 0xFFFF * 8)
            {
            // UWOP_ALLOC_LARGE (16-bit)
            u8 op   = 1;
            u8 info = 0;

            push_u8(4);
            push_u8((info << 4) | op);

            push_u16(stackSize / 8);
            }
        else
            {
            // UWOP_ALLOC_LARGE (32-bit)
            u8 op   = 1;
            u8 info = 1;

            push_u8(4);
            push_u8((info << 4) | op);

            push_u32(stackSize);
            }
        }

        // align 4 (inutile car toujours aligné avec cela uniquement)
        while (content.size() % 4)
            content.push_back(0);

        if (unwindFlags!=0x0){
            // Exception handler RVA
            push_u32(sehHandlerRva);
            // Exception data (optionnel)
            push_u32(0);
        }

        // enregistrer le bloc
        blocks.push_back({ id, rva, sehHandlerRva });
    }

    // Obtenir l'adresse complète d'un bloc par son ID
    u32 get_block_rva(int id, u32 sectionVirtualAddress) const {
        for (const auto& b : blocks) {
            if (b.id == id)
                return sectionVirtualAddress + b.rva;
        }
        return 0; // pas trouvé
    }

    u32 get_size() const { return static_cast<u32>(content.size()); }
};


//code pour l'assembleur keystone
vector<u8> assemble(const char* code) {
    ks_engine* ks;
    if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) throw runtime_error("ks_open failed");
    unsigned char* encode;
    size_t size, count;
    if (ks_asm(ks, code, 0, &encode, &size, &count) != KS_ERR_OK) {
        ks_close(ks);
        throw runtime_error("ks_asm failed");
    }
    vector<u8> v(encode, encode + size);
    ks_free(encode);
    ks_close(ks);
    return v;
}

//afficheur du code generer deboggage
void print_hex(const std::vector<uint8_t>& buf)
{
    for (size_t i = 0; i < buf.size(); ++i)
    {
        if (i % 16 == 0)
            std::cout << std::endl;

        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)buf[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

//exemple 1 (premier teste reel fonctionnel)

/*
//affiche juste un printf Hello word puis exit
int main() {
    IDATA idata;
    idata.add_import("msvcrt.dll", {"printf"});
    idata.add_import("kernel32.dll", {"ExitProcess"});

    // Prépare la section .idata //layout() automatique respecte les sections
    idata.prepare();


    PEBuilder pb; //créer la section text en premier

    // Récupère le contenu de la section .idata
    std::vector<u8> idata_content = idata.get_content();

    // Ajoute la section .idata à votre PEBuilder
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
    pb.push_section(idata_section);

    pb.layout(); //initialiser les adresses

    //refaire avec les vrai adresses absolu
    u32 idata_virtualadress = pb.get_section(1).virtualAddress;
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    idata.reprepare(idata_virtualadress); //refaire avec adresse absolu

     Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section);

    pb.layout(); //initialiser les adresses

    pb.set_data_directory(1, idata_virtualadress, pb.get_section(1).sizeOfRawData); //idata_virtualsize

    // Ajoute des données dans une section dédiée
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040);
    dataSection.content={}; //vide sinon valeur automatique 0x90 *4
    const char msg[] = "Hello World\n\0";
    size_t msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg, msg + sizeof(msg));

    // Calcule les adresses virtuelles et physiques des sections
    pb.layout();

    // Code assembleur
    u32 text_rva = pb.text().virtualAddress;
    u32 msg_rva = pb.get_data_rva(2, msg_offset); // 2 est l'index de la section .data
    u64 printf_rva = static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf",idata_virtualadress))+IMAGE_BASE;
    u64 exit_rva = static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess",idata_virtualadress))+IMAGE_BASE;

    //int next_after_lea = (int)(text_rva + 4 + 7);
    //int next_after_call = (int)(text_rva + 4 + 7 + 6);
    //int32_t disp_msg = (int32_t)(msg_rva - next_after_lea);
    //int32_t disp_printf = (int32_t)(printf_rva - next_after_call);
    //int32_t disp_exit = (int32_t)(exit_rva - (next_after_call + 2 + 6));

    u64 msg_va = IMAGE_BASE + static_cast<u64>(msg_rva); //conversion va machine avec l'image base
    u64 printf_va = idata.get_import_va("msvcrt.dll", "printf", IMAGE_BASE);
    u64 exit_va = idata.get_import_va("kernel32.dll", "ExitProcess", IMAGE_BASE);

    string asm_code =
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"

    "sub rsp, 28h\n"                                      // align stack (Windows x64)
    "mov rcx, " + to_string(msg_va) + "\n"                // RCX = ptr vers la chaîne (arg1 pour printf)
    // --- appeler printf via son IAT ---
    "mov rax, " + to_string(printf_rva) + "\n"         // RAX = adresse de l'entrée IAT (pointer vers l'adresse de la fonction)
    "mov rax, [rax]\n"                                    // RAX = valeur contenue dans l'IAT (adresse réelle de printf)
    "call rax\n"                                          // call printf
    // --- préparer exit(0) ---
    "xor ecx, ecx\n"                                      // ECX = 0 (exit code)
    // --- appeler ExitProcess via son IAT ---
    "mov rax, " + to_string(exit_rva) + "\n"           // RAX = adresse de l'entrée IAT pour ExitProcess
    "mov rax, [rax]\n"                                    // RAX = adresse réelle d'ExitProcess
    "call rax\n";                                         // call ExitProcess (ne revient pas)

    pb.text().content = assemble(asm_code.c_str());

    print_hex(pb.text().content);

    // Construit le PE
    size_t entry_rva_ = pb.text().virtualAddress + 32; //(décalage de 32 nop avant début)
    vector<u8> pe = pb.build(entry_rva_);

    // Écrit le fichier
    HANDLE f = CreateFileA("out.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    pb.see_section();

    std::cout << "RVA de printf : " << std::hex << printf_rva << std::endl;
    std::cout << "RVA de ExitProcess : " << std::hex << exit_rva << std::endl;
    std::cout << "VA de printf : " << std::hex << printf_va << std::endl;
    std::cout << "VA de ExitProcess : " << std::hex << exit_va << std::endl;

    return 0;
}*/

//exemple 2

/*
//affiche 2 fois avec puts et printf
int main() {
    IDATA idata;
    idata.add_import("msvcrt.dll", {"printf", "puts"});
    idata.add_import("kernel32.dll", {"ExitProcess"});

    // Prépare la section .idata //layout() automatique respecte les sections
    idata.prepare();


    PEBuilder pb; //créer la section text en premier (index 0)

    // Récupère le contenu de la section .idata
    std::vector<u8> idata_content = idata.get_content();

    // Ajoute la section .idata à votre PEBuilder
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA

    pb.push_section(idata_section); //écrit la nouvelle section

    pb.layout(); //initialiser les adresses (Pour pouvoir reconstruire idata avec les vrai adresses)

    //refaire avec les vrai adresses absolu
    u32 idata_virtualadress = pb.get_section(1).virtualAddress; //1= section 2 car la section text à l'index 0
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    idata.reprepare(idata_virtualadress); //refaire avec adresse absolu

     Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section); //remplace une section d'un index par la nouvelle fournit

    pb.layout(); //initialiser les adresses

    pb.set_data_directory(1, idata_virtualadress, pb.get_section(1).sizeOfRawData); //idata_virtualsize

    // Ajoute des données dans une section dédiée
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040); //section créer sans devoir tout fournir comme push_section()
    dataSection.content={}; //vidé sinon valeur automatique 0x90 *4 ( ! ne pas envoyé une section vide dans layout sinon décale tout)
    const char msg[] = "Hello World\n\0";
    size_t msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg, msg + sizeof(msg));

    const char msg2[] = "Hello puts\0";
    size_t msg2_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg2, msg2 + sizeof(msg2));

    // Calcule les adresses virtuelles et physiques des sections
    pb.layout();

    // Code assembleur
    u32 text_rva = pb.text().virtualAddress; //text() peut être remplacer par get_section(0) vu que text est la première section

    u32 msg_rva = pb.get_data_rva(2, msg_offset); // 2 est l'index de la section .data
    u32 msg2_rva = pb.get_data_rva(2, msg2_offset);

    u64 printf_rva = static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf",idata_virtualadress))+IMAGE_BASE;
    u64 puts_rva = static_cast<u64>(idata.get_import_rva("msvcrt.dll", "puts", idata_virtualadress))+ IMAGE_BASE;
    u64 exit_rva = static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess",idata_virtualadress))+IMAGE_BASE;


    u64 msg_va = IMAGE_BASE + static_cast<u64>(msg_rva); //conversion va machine avec l'image base
    u64 msg2_va = IMAGE_BASE + static_cast<u64>(msg2_rva); //conversion va machine avec l'image base

    string asm_code =
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"
    "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n" "nop\n"

    "sub rsp, 28h\n"                                      // align stack (Windows x64)
    "mov rcx, " + to_string(msg_va) + "\n"                // RCX = ptr vers la chaîne (arg1 pour printf)
    // --- appeler printf via son IAT ---
    "mov rax, " + to_string(printf_rva) + "\n"         // RAX = adresse de l'entrée IAT (pointer vers l'adresse de la fonction)
    "mov rax, [rax]\n"                                    // RAX = valeur contenue dans l'IAT (adresse réelle de printf)
    "call rax\n"                                          // call printf

    "mov rcx, " + to_string(msg2_va) + "\n"
    "mov rax, " + to_string(puts_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"

    // --- préparer exit(0) ---
    "xor ecx, ecx\n"                                      // ECX = 0 (exit code)
    // --- appeler ExitProcess via son IAT ---
    "mov rax, " + to_string(exit_rva) + "\n"           // RAX = adresse de l'entrée IAT pour ExitProcess
    "mov rax, [rax]\n"                                    // RAX = adresse réelle d'ExitProcess
    "call rax\n";                                         // call ExitProcess (ne revient pas)

    pb.text().content = assemble(asm_code.c_str()); //fonction avec keystone qui converti l'assembleur en code machine pour windows 64 bits

    print_hex(pb.text().content); //affiche le code machine générer par keystone

    // Construit le PE
    size_t entry_rva_ = pb.text().virtualAddress + 32; //(décalage de 32 nop avant début mais pas obligatoire on peut mettre aucun nop et ça marche aussi)
    vector<u8> pe = pb.build(entry_rva_);

    // Écrit le fichier
    HANDLE f = CreateFileA("out2.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    pb.see_section();

    std::cout << "RVA de printf : " << std::hex << printf_rva << std::endl;
    std::cout << "RVA de puts : " << std::hex << puts_rva << std::endl;
    std::cout << "RVA de ExitProcess : " << std::hex << exit_rva << std::endl;

    return 0;
}
*/

//exemple 3

/*
//creer des printf dans un thread simple puis quand le programme est finit, sort
int main() {
    IDATA idata;
    // Imports : deux fonctions dans msvcrt et CreateThread + WaitForSingleObject + ExitProcess depuis kernel32
    idata.add_import("msvcrt.dll", {"printf", "puts"});
    idata.add_import("kernel32.dll", {"CreateThread", "WaitForSingleObject", "ExitProcess"});

    // Prépare la section .idata (layout interne de IDATA)
    idata.prepare();

    PEBuilder pb; // créer la section .text en premier (index 0)

    // Récupère le contenu initial de .idata et l'ajoute comme section temporaire
    std::vector<u8> idata_content = idata.get_content();
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // READ | WRITE | INITIALIZED_DATA
    pb.push_section(idata_section);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .idata et sa taille
    u32 idata_virtualadress = pb.get_section(1).virtualAddress; // index 1 => .idata
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    // Refaire l'idata avec les RVA corrects
    idata.reprepare(idata_virtualadress);

    Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section);

    // Re-layout après correction
    pb.layout();

    // Fixe la data directory import
    pb.set_data_directory(1, idata_virtualadress, pb.get_section(1).sizeOfRawData);

    // Ajoute section .data puis les chaînes utilisées
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040);
    dataSection.content = {}; // empty initially

    const char msg1[] = "Thread printing: Hello printf\n";
    size_t msg1_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg1, msg1 + sizeof(msg1));

    const char msg2[] = "Thread printing: Hello puts\n";
    size_t msg2_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg2, msg2 + sizeof(msg2));

    const char done_msg[] = "FINI !\n";
    size_t done_msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), done_msg, done_msg + sizeof(done_msg));

    // Re-layout afin d'obtenir les RVAs finales
    pb.layout();


    //RSRC section
    RSRC rsrc;

    rsrc.add_version_full(L"1.0.0.0",L"1.0.0.0",L"argentrocher",L"test",L"out.exe",L"out.exe",L"argentroger@gmail.com"); //version visible dans détail sur windows
    rsrc.add_icon_from_file("frc.ico"); //chemin fichier ico (l'image est gravé dans l'exe au moment de ça création, ce n'est pas une redirection)
    rsrc.add_manifest("out.exe","1.0.0.0",false,false,false,false); //manifest pour la sécurité et conformité windows (2 preimer bool= GUI affichage, 3 bool= admin nécessaire ou non 4 bool commonControlsV6 pour certaines fonctions de code asm qui utilise rt_dialog)

    rsrc.build(0); //build avec adresse inconnu de virtual adresse donc 0

    Section s;
    s.name = ".rsrc";
    s.content = rsrc.content;
    s.virtualAddress = 0x0;
    s.virtualSize = s.content.size();
    s.sizeOfRawData = s.content.size();
    s.characteristics = 0x40000040;

    pb.push_section(s);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .rsrc et sa taille
    u32 rsrc_virtualadress = pb.get_section(3).virtualAddress; // index 3 => .rsrc
    u32 rsrc_virtualsize = pb.get_section(3).virtualSize;

    rsrc.build(rsrc_virtualadress); //buid à nouveau avec la vrai adresse virtuel (écrasse le premier créer car faux)

    Section corrected_s;
    corrected_s.name = ".rsrc";
    corrected_s.content = rsrc.content;
    corrected_s.virtualAddress = rsrc_virtualadress;
    corrected_s.virtualSize = rsrc_virtualsize;
    corrected_s.sizeOfRawData = pb.get_section(3).sizeOfRawData;
    corrected_s.pointerToRawData = pb.get_section(3).pointerToRawData;
    corrected_s.characteristics = 0x40000040;

    pb.replace_section(3, corrected_s);

    // Re-layout après correction
    pb.layout();

    // Fixe la rsrc directory import
    pb.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, rsrc_virtualadress, pb.get_section(3).sizeOfRawData); //écrire dans la table de directory du PE la section


    // RVAs et VAs utiles
    u32 text_rva = pb.text().virtualAddress;
    u32 msg1_rva = pb.get_data_rva(2, msg1_offset);   // section index 2 == .data (comme dans ton code)
    u32 msg2_rva = pb.get_data_rva(2, msg2_offset);
    u32 done_msg_rva = pb.get_data_rva(2, done_msg_offset);

    u64 msg1_va = IMAGE_BASE + static_cast<u64>(msg1_rva);
    u64 msg2_va = IMAGE_BASE + static_cast<u64>(msg2_rva);
    u64 done_msg_va = IMAGE_BASE + static_cast<u64>(done_msg_rva);

    // IAT entries (VA of the IAT slot) -> image base + RVA returned by idata.get_import_rva()
    u64 printf_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf", idata_virtualadress));
    u64 puts_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "puts",   idata_virtualadress));
    u64 create_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "CreateThread", idata_virtualadress));
    u64 wait_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "WaitForSingleObject", idata_virtualadress));
    u64 exit_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess", idata_virtualadress));

    // --- ASSEMBLE: 1) thread function bytes (we'll place it AT THE START of .text) ---
    // Thread function: boucle 10 fois et appelle printf via IAT
    string thread_asm =
        // prologue for thread
        "sub rsp, 40h\n"
        //"mov qword ptr [rsp+32], r12\n" //save r12 in stack slot (offset depends on your sub rsp)
        // we will use rsi as loop counter
        "mov r12d, 0xA\n"                    // counter = 10
    ".thread_loop:\n"
        "mov rax, " + to_string(printf_iat_va) + "\n"  // address of printf IAT entry
        "mov rax, [rax]\n"                 // rax = real printf address
        "mov rcx, " + to_string(msg1_va) + "\n"   // arg1 = msg1
        //"xor al, al\n"
        "call rax\n"
        "dec r12d\n"          //r12--
        "jnz .thread_loop\n"
        //restore r12
        //"mov r12, qword ptr [rsp+32]\n"
        // cleanup and return
        "xor eax, eax\n"    // thread return = 0
        "add rsp, 40h\n"
        "ret\n";

    // Assemble thread function into bytes
    vector<u8> thread_bytes = assemble(thread_asm.c_str());

    // --- 2) MAIN code that creates the thread, waits, prints final message and exit ---
    // Compute thread start VA (it will be at start of .text section)
    u64 thread_start_va = IMAGE_BASE + static_cast<u64>(pb.text().virtualAddress); // because we will put thread first
    // Note: main entry will be placed right after thread_bytes in .text content

    // Main assembly: create thread, wait for it, then printf("Terminé\n"), ExitProcess(0)
    // We'll allocate a 64 bytes stack frame for shadow space and extra 5/6th args.
    string main_asm =
        // prologue for main - reserve shadow + extra stack space
        "sub rsp, 40h\n"

        // Prepare CreateThread parameters:
        // RCX = lpThreadAttributes = NULL
        // RDX = dwStackSize = 0
        // R8  = lpStartAddress = thread_start_va
        // R9  = lpParameter = NULL
        // on stack: dwCreationFlags (DWORD) at [rsp+32] = 0
        //           lpThreadId (QWORD) at [rsp+40] = 0
        "xor rcx, rcx\n"
        "xor rdx, rdx\n"
        "mov r8, " + to_string(thread_start_va) + "\n"
        "xor r9, r9\n"
        // store dwCreationFlags (dword) at [rsp+32] = 0
        "mov dword ptr [rsp+32], 0\n"
        // store lpThreadId (qword) at [rsp+40] = 0
        "mov qword ptr [rsp+40], 0\n"

        // call CreateThread via IAT
        "mov rax, " + to_string(create_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        // RAX = thread handle

        // Wait for thread: WaitForSingleObject(handle, INFINITE)
        "mov rcx, rax\n"                         // handle
        "mov rdx, -1\n"                         // INFINITE (0xFFFFFFFF)
        "mov rax, " + to_string(wait_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 40h\n"

        // Print final message: puts("Terminé\n")
        "mov rcx, " + to_string(done_msg_va) + "\n"
        "mov rax, " + to_string(puts_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // ExitProcess(0)
        "xor ecx, ecx\n"
        "mov rax, " + to_string(exit_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        ;

    // Assemble main
    vector<u8> main_bytes = assemble(main_asm.c_str());

    // Build final .text content: thread_bytes followed by main_bytes
    vector<u8> final_text;
    final_text.insert(final_text.end(), thread_bytes.begin(), thread_bytes.end());
    final_text.insert(final_text.end(), main_bytes.begin(), main_bytes.end());

    // Optionally pad to maintain alignment (not strictly required here)
    pb.text().content = final_text;

    // Debug print
    print_hex(pb.text().content);

    // Construit le PE avec l'entry point = pb.text().virtualAddress + offset where main starts
    size_t entry_rva_ = pb.text().virtualAddress + thread_bytes.size() + 0; // optionally +32 for extra NOP if you want
    vector<u8> pe = pb.build(entry_rva_);

    // write file
    HANDLE f = CreateFileA("out_thread.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    // show sections and debug info as you had
    pb.see_section();

    std::cout << "Thread start VA: " << std::hex << thread_start_va << std::endl;
    std::cout << "entry_rva (main) : " << std::hex << entry_rva_ << std::endl;
    std::cout << "printf_iat_va: " << std::hex << printf_iat_va << std::endl;
    std::cout << "create_iat_va: " << std::hex << create_iat_va << std::endl;
    std::cout << "wait_iat_va: " << std::hex << wait_iat_va << std::endl;
    std::cout << "exit_iat_va: " << std::hex << exit_iat_va << std::endl;

    return 0;
}
*/

//exemple 4

/*
//fenêtre dialog bouton
int main() {
    IDATA idata;
    // Imports : deux fonctions dans msvcrt et CreateThread + WaitForSingleObject + ExitProcess depuis kernel32
    idata.add_import("msvcrt.dll", {"printf", "puts"});
    idata.add_import("kernel32.dll", {"CreateThread", "WaitForSingleObject", "GetModuleHandleW", "ExitProcess"});
    idata.add_import("user32.dll", {"DialogBoxParamW", "EndDialog"});

    // Prépare la section .idata (layout interne de IDATA)
    idata.prepare();

    PEBuilder pb; // créer la section .text en premier (index 0)

    // Récupère le contenu initial de .idata et l'ajoute comme section temporaire
    std::vector<u8> idata_content = idata.get_content();
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // READ | WRITE | INITIALIZED_DATA
    pb.push_section(idata_section);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .idata et sa taille
    u32 idata_virtualadress = pb.get_section(1).virtualAddress; // index 1 => .idata
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    // Refaire l'idata avec les RVA corrects
    idata.reprepare(idata_virtualadress);

    Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section);

    // Re-layout après correction
    pb.layout();

    // Fixe la data directory import
    pb.set_data_directory(1, idata_virtualadress, pb.get_section(1).sizeOfRawData);

    // Ajoute section .data puis les chaînes utilisées
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040);
    dataSection.content = {}; // empty initially

    const char msg1[] = "Thread printing: Hello printf\n";
    size_t msg1_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg1, msg1 + sizeof(msg1));

    const char msg2[] = "Thread printing: Hello puts\n";
    size_t msg2_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg2, msg2 + sizeof(msg2));

    const char done_msg[] = "FINI !\n";
    size_t done_msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), done_msg, done_msg + sizeof(done_msg));

    // Zone mémoire pour construire le message final
    const char msg_prefix[] = "Boutton clic id: ";
    size_t msg_prefix_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg_prefix, msg_prefix + sizeof(msg_prefix));

    const char button_buf[16] = {0};  // buffer pour convertir le nombre en ASCII
    size_t button_buf_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), button_buf, button_buf + sizeof(button_buf));

    // Re-layout afin d'obtenir les RVAs finales
    pb.layout();


    //RSRC section
    RSRC rsrc;

    rsrc.add_version_full(L"1.0.0.0",L"1.0.0.0",L"argentrocher",L"test",L"out.exe",L"out.exe",L"argentroger google account"); //version visible dans détail sur windows
    rsrc.add_icon_from_file("frc.ico"); //chemin fichier ico (l'image est gravé dans l'exe au moment de ça création, ce n'est pas une redirection)
    rsrc.add_manifest("out.exe","1.0.0.0",false,false,false,false); //manifest pour la sécurité et conformité windows (2 preimer bool= GUI affichage, 3 bool= admin nécessaire ou non 4 bool commonControlsV6 pour certaines fonctions de code asm qui utilise rt_dialog)


    RSRC::DialogDesc d;
    d.id = 4; //id (attention, id utilisé dans le code asm)
    d.title = L"Test DialogBoxParamW"; //titre de la fenêtre
    d.x = 0; d.y = 0; d.width = 180; d.height = 80; //dimension, coordonée d'apparition
    d.italic=true; //italque (true false)
    d.size_point=8; //taille texte et fenêtre (8=standard)
    d.weight=0; //poids

    d.controls.push_back({RSRC::DialogControl::Type::BUTTON, true, 1001, L"OK", 20,40,40,14});
    d.controls.push_back({RSRC::DialogControl::Type::BUTTON, true, 1002, L"Cancel", 120,40,40,14});
    d.controls.push_back({RSRC::DialogControl::Type::LABEL, true, 0, L"Choisissez une option :", 10,20,160,20});

    rsrc.add_dialog(d);

    rsrc.build(0); //build avec adresse inconnu de virtual adresse donc 0

    Section s;
    s.name = ".rsrc";
    s.content = rsrc.content;
    s.virtualAddress = 0x0;
    s.virtualSize = s.content.size();
    s.sizeOfRawData = s.content.size();
    s.characteristics = 0x40000040;

    pb.push_section(s);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .rsrc et sa taille
    u32 rsrc_virtualadress = pb.get_section(3).virtualAddress; // index 3 => .rsrc
    u32 rsrc_virtualsize = pb.get_section(3).virtualSize;

    rsrc.build(rsrc_virtualadress); //buid à nouveau avec la vrai adresse virtuel (écrasse le premier créer car faux)

    Section corrected_s;
    corrected_s.name = ".rsrc";
    corrected_s.content = rsrc.content;
    corrected_s.virtualAddress = rsrc_virtualadress;
    corrected_s.virtualSize = rsrc_virtualsize;
    corrected_s.sizeOfRawData = pb.get_section(3).sizeOfRawData;
    corrected_s.pointerToRawData = pb.get_section(3).pointerToRawData;
    corrected_s.characteristics = 0x40000040;

    pb.replace_section(3, corrected_s);

    // Re-layout après correction
    pb.layout();

    // Fixe la rsrc directory import
    pb.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, rsrc_virtualadress, pb.get_section(3).sizeOfRawData); //écrire dans la table de directory du PE la section


    // RVAs et VAs utiles
    u32 text_rva = pb.text().virtualAddress;
    u32 msg1_rva = pb.get_data_rva(2, msg1_offset);   // section index 2 == .data (comme dans ton code)
    u32 msg2_rva = pb.get_data_rva(2, msg2_offset);
    u32 done_msg_rva = pb.get_data_rva(2, done_msg_offset);
    u32 msg_prefix_rva = pb.get_data_rva(2, msg_prefix_offset); //chaine fixe de texte
    u32 button_buf_rva = pb.get_data_rva(2, button_buf_offset); //emplacement de l'écriture de la valeur id pressed

    u64 msg1_va = IMAGE_BASE + static_cast<u64>(msg1_rva);
    u64 msg2_va = IMAGE_BASE + static_cast<u64>(msg2_rva);
    u64 done_msg_va = IMAGE_BASE + static_cast<u64>(done_msg_rva);
    u64 msg_prefix_va = IMAGE_BASE + static_cast<u64>(msg_prefix_rva);
    u64 button_buf_va = IMAGE_BASE + static_cast<u64>(button_buf_rva);

    // IAT entries (VA of the IAT slot) -> image base + RVA returned by idata.get_import_rva()
    u64 printf_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf", idata_virtualadress));
    u64 puts_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "puts",   idata_virtualadress));
    u64 create_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "CreateThread", idata_virtualadress));
    u64 wait_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "WaitForSingleObject", idata_virtualadress));
    u64 exit_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess", idata_virtualadress));
    u64 dialogbox_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "DialogBoxParamW", idata_virtualadress));
    u64 enddialog_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "EndDialog", idata_virtualadress));
    u64 getmodule_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "GetModuleHandleW", idata_virtualadress));


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
    "xor eax, eax\n"
    "jmp .exit\n"

    ".init:\n"
    "mov eax, 1\n"
    "jmp .exit\n"

    ".command:\n"

    "sub rsp, 28h\n"

    "movzx eax, r8w\n"           // id du bouton cliqué
    "mov rcx, rcx\n"            // hwnd
    "xor edx, edx\n"
    "mov edx, eax\n"            //id du bouton pour enddialog
    "mov rax, " + to_string(enddialog_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"

    "add rsp, 28h\n"

    "mov eax, 1\n" //dire à DialogBoxParam que WM_COMMAND est traité

    "jmp .exit\n"

    ".exit:\n"
    "pop rdi\n"
    "pop rsi\n"
    "pop rbx\n"
    "ret\n"
    ;

    // Assemble thread function into bytes
    vector<u8> dialog_proc_bytes = assemble(dialog_proc_asm.c_str());

    // --- 2) MAIN code that creates the thread, waits, prints final message and exit ---
    // Compute thread start VA (it will be at start of .text section)
    u64 dialog_proc_va = IMAGE_BASE + static_cast<u64>(pb.text().virtualAddress); // because we will put thread first
    // Note: main entry will be placed right after thread_bytes in .text content

    // Main assembly: create thread, wait for it, then printf("Terminé\n"), ExitProcess(0)
    // We'll allocate a 64 bytes stack frame for shadow space and extra 5/6th args.
    string main_asm =
        // prologue for main - reserve shadow + extra stack space
        "sub rsp, 28h\n"

        // hInstance = GetModuleHandleW(NULL)
        "xor rcx, rcx\n"
        "mov rax, " + to_string(getmodule_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // DialogBoxParamW(hInst, ID=1, NULL, dialog_proc, 0)
        "mov rcx, rax\n"                        // hInstance
        "mov rdx, 4\n"                          // MAKEINTRESOURCEW(4)   (on a donné comme id 4 la rt_dialog)
        "xor r8, r8\n"                          // parent = NULL
        "mov r9, " + to_string(dialog_proc_va) + "\n"

        "mov qword ptr [rsp+20h], 0\n"

        "mov rax, " + to_string(dialogbox_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        "mov rbx, rax\n"  //sauvgarde de l'id du bouton cliqué

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // Print final message: puts("Terminé\n")
        "mov rcx, " + to_string(done_msg_va) + "\n"
        "mov rax, " + to_string(puts_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"


        "mov rdi, " + to_string(msg_prefix_va) + "\n"    // RDI pointe sur le début du message
        "mov rax, rbx\n"                 // RBX = ID du bouton
        "mov rcx, 10\n"                  // diviseur pour conversion décimale
        "mov rsi, "+ to_string(button_buf_va) + "\n" //debut buffer
        "add rsi, 15\n"                  // pointe sur la fin du buffer (car taille 16)
        "mov byte ptr [rsi], 0\n"        // null terminate

        ".convert_loop:\n"
        "xor rdx, rdx\n"
        "div rcx\n"                       // rax = quotient, rdx = remainder
        "add dl, '0'\n"                    // convertir chiffre en ASCII
        "dec rsi\n"
        "mov [rsi], dl\n"
        "mov rax, rax\n"
        "test rax, rax\n"
        "jnz .convert_loop\n"

        // concaténer le nombre après le prefix
        // RDI = msg_prefix, RSI = début du nombre ASCII
        "mov rdx, rsi\n"                  // adresse début du nombre
        "jmp .strcat_ascii_to_prefix\n"     // fonction simple qui copie la chaîne terminée par 0 de RDX à la fin de RDI

        ".after_ascii_to_prefix:\n"

        // appeler puts (affiche l'id du bouton clic)
        "mov rcx, " + to_string(msg_prefix_va) + "\n"       // RCX = pointeur sur la chaîne complète (donc le premier msg (! il faut que les messages se suivent dans la création de data sinon échec n'affichera que la chaîne statique))
        "mov rax," + to_string(puts_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // ExitProcess(0)
        "xor ecx, ecx\n"
        "mov rax, " + to_string(exit_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        "ret\n"

        //terminer au dessus

        //(en dessous une fonction)

        //fonction de concat ascii
        ".strcat_ascii_to_prefix:\n"
        //RDI = destination, RDX = source
        ".find_end_dest:\n"
            "cmp byte ptr [rdi], 0\n"
            "je .copy_src\n"
            "inc rdi\n"
            "jmp .find_end_dest\n"
        ".copy_src:\n"
            "mov al, [rdx]\n"
            "mov [rdi], al\n"
            "cmp al, 0\n"
            "je .done\n"
            "inc rdi\n"
            "inc rdx\n"
            "jmp .copy_src\n"
        ".done:\n"
            "jmp .after_ascii_to_prefix\n"
        ;

    // Assemble main
    vector<u8> main_bytes = assemble(main_asm.c_str());

    // Build final .text content: dialog_bytes followed by main_bytes
    vector<u8> final_text;
    final_text.insert(final_text.end(), dialog_proc_bytes.begin(), dialog_proc_bytes.end());
    final_text.insert(final_text.end(), main_bytes.begin(), main_bytes.end());

    // Optionally pad to maintain alignment (not strictly required here)
    pb.text().content = final_text;

    // Debug print
    print_hex(pb.text().content);

    // Construit le PE avec l'entry point = pb.text().virtualAddress + offset where main starts
    size_t entry_rva_ = pb.text().virtualAddress + dialog_proc_bytes.size() + 0; // optionally +32 for extra NOP if you want
    vector<u8> pe = pb.build(entry_rva_);

    // write file
    HANDLE f = CreateFileA("out_dialog.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    // show sections and debug info as you had
    pb.see_section();

    std::cout << "Thread start VA: " << std::hex << dialog_proc_va << std::endl;
    std::cout << "entry_rva (main) : " << std::hex << entry_rva_ << std::endl;
    std::cout << "printf_iat_va: " << std::hex << printf_iat_va << std::endl;
    std::cout << "create_iat_va: " << std::hex << create_iat_va << std::endl;
    std::cout << "wait_iat_va: " << std::hex << wait_iat_va << std::endl;
    std::cout << "exit_iat_va: " << std::hex << exit_iat_va << std::endl;

    return 0;
}
*/

//exemple 5

/*
//fenêtre dialog saisie (avec couleur en plus donc diférent du premier dialog car le code pour les couleurs est appeler avec les fonctions assembleur)
int main() {
    IDATA idata;
    // Imports : deux fonctions dans msvcrt et CreateThread + WaitForSingleObject + ExitProcess depuis kernel32
    idata.add_import("msvcrt.dll", {"printf", "puts"});
    idata.add_import("kernel32.dll", {"CreateThread", "WaitForSingleObject", "GetModuleHandleW", "ExitProcess", "lstrlenW"});
    idata.add_import("user32.dll", {"DialogBoxParamW", "EndDialog", "GetDlgItemTextW", "SendDlgItemMessageW"});
    idata.add_import("gdi32.dll", {"CreateSolidBrush", "GetStockObject", "Ellipse", "Rectangle", "TextOutW", "SetTextColor", "SetBkMode", "SelectObject", "DeleteObject"});

    // Prépare la section .idata (layout interne de IDATA)
    idata.prepare();

    PEBuilder pb; // créer la section .text en premier (index 0)

    // Récupère le contenu initial de .idata et l'ajoute comme section temporaire
    std::vector<u8> idata_content = idata.get_content();
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // READ | WRITE | INITIALIZED_DATA
    pb.push_section(idata_section);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .idata et sa taille
    u32 idata_virtualadress = pb.get_section(1).virtualAddress; // index 1 => .idata
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    // Refaire l'idata avec les RVA corrects
    idata.reprepare(idata_virtualadress);

    Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section);

    // Re-layout après correction
    pb.layout();

    // Fixe la data directory import
    pb.set_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT, idata_virtualadress, pb.get_section(1).sizeOfRawData);

    // Ajoute section .data puis les chaînes utilisées
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040);
    dataSection.content = {}; // empty initially

    const char msg1[] = "Cancel !\n";
    size_t msg1_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg1, msg1 + sizeof(msg1));

    const char msg2[] = "Closed !\n";
    size_t msg2_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg2, msg2 + sizeof(msg2));

    const char done_msg[] = "FINI !\n";
    size_t done_msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), done_msg, done_msg + sizeof(done_msg));

    // Zone pour le message du texte fixe au dessus du EDIT
    const wchar_t msg_label[] = L"Choisissez une option :";
    size_t msg_label_offset = dataSection.content.size();
    dataSection.content.insert(
    dataSection.content.end(),
    reinterpret_cast<const u8*>(msg_label),
    reinterpret_cast<const u8*>(msg_label + sizeof(msg_label)/sizeof(wchar_t))
    );

    // Zone pour le message de l'edit en arrière plan
    const wchar_t msg_prefix[] = L"entre ton texte ...";
    size_t msg_prefix_offset = dataSection.content.size();
    dataSection.content.insert(
    dataSection.content.end(),
    reinterpret_cast<const u8*>(msg_prefix),
    reinterpret_cast<const u8*>(msg_prefix + sizeof(msg_prefix)/sizeof(wchar_t))
    );

    const char entry_buf_w[512] = {0};  // buffer de texte réponse (512 car la taile d'un 256 char standard vu que l'on écrit la conversion)
    size_t entry_buf_w_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), entry_buf_w, entry_buf_w + sizeof(entry_buf_w));

    const char entry_buf_a[256] = {0};
    size_t entry_buf_a_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), entry_buf_a, entry_buf_a + sizeof(entry_buf_a));

    const char buffer_adr[16] = {0}; //buffer pour savoir quel adresse pointer pour afficher la réponse
    size_t buf_adr_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), buffer_adr, buffer_adr + sizeof(buffer_adr));

    // Re-layout afin d'obtenir les RVAs finales
    pb.layout();


    //RSRC section
    RSRC rsrc;

    rsrc.add_version_full(L"1.0.0.0",L"1.0.0.0",L"argentrocher",L"test",L"out.exe",L"out.exe",L"argentroger google account"); //version visible dans détail sur windows
    rsrc.add_icon_from_file("frc.ico"); //chemin fichier ico (l'image est gravé dans l'exe au moment de ça création, ce n'est pas une redirection)
    rsrc.add_manifest("out.exe","1.0.0.0",false,false,false,true); //manifest pour la sécurité et conformité windows (2 preimer bool= GUI affichage, 3 bool= admin nécessaire ou non 4 bool commonControlsV6 pour certaines fonctions de code asm qui utilise rt_dialog)


    RSRC::DialogDesc d;
    d.id = 4; //id (attention, id utilisé dans le code asm)
    d.title = L"Test DialogBoxParamW"; //titre de la fenêtre
    d.x = 100; d.y = 100; d.width = 180; d.height = 80; //dimension, coordonée d'apparition
    d.italic=false; //italque (true false)
    d.size_point=12; //taille texte et fenêtre (8=standard)
    d.weight=0; //poids

    // ! lordre des controls est important, le premier est celui qui a le focus en priorité (avantage de DEFBUTTON est le enter automatique dessus même si on est sur un EDIT mi en premier)
    d.controls.push_back({RSRC::DialogControl::Type::DRAWRECT, true, 1000, L"", 0,0,180,80}); //mon fond code asm pour couleur
    //d.controls.push_back({RSRC::DialogControl::Type::LABEL, true, 0, L"Choisissez une option :", 20,15,75,10}); //-> label,le fond n'est pas controlable donc c'est bien pour un font standard sinon il faut écrire en asm avec DrawTextW dans un ss_ownerdraw
    d.controls.push_back({RSRC::DialogControl::Type::EDIT, true, 1003, L"...", 20,35,140,12}); //mi en premier de type TABSTOP pour avoir le curseur dessus
    d.controls.push_back({RSRC::DialogControl::Type::DEFBUTTON, true, 1001, L"OK", 20,55,40,16});
    d.controls.push_back({RSRC::DialogControl::Type::BUTTON, true, 1002, L"Cancel", 120,55,40,16});
    d.controls.push_back({RSRC::DialogControl::Type::DRAWRECT, true, 1004, L"", 148,2,30,30}); //rectangle dessinable avec ownerdraw
    //autre commande possible pour forme sans code asm
    //d.controls.push_back({RSRC::DialogControl::Type::FILLRECT, true, 0, L"", 0,0,20,20}); //creer un regtangle gris plein (non modifiable) (FRAMERECT creer un rectangle vide contour noir non modifiable)

    rsrc.add_dialog(d);

    rsrc.build(0); //build avec adresse inconnu de virtual adresse donc 0

    Section s;
    s.name = ".rsrc";
    s.content = rsrc.content;
    s.virtualAddress = 0x0;
    s.virtualSize = s.content.size();
    s.sizeOfRawData = s.content.size();
    s.characteristics = 0x40000040;

    pb.push_section(s);

    // Layout initial pour connaître les RVAs (text .virtualAddress etc.)
    pb.layout();

    // Récupère l'adresse virtuelle de la section .rsrc et sa taille
    u32 rsrc_virtualadress = pb.get_section(3).virtualAddress; // index 3 => .rsrc
    u32 rsrc_virtualsize = pb.get_section(3).virtualSize;

    rsrc.build(rsrc_virtualadress); //buid à nouveau avec la vrai adresse virtuel (écrasse le premier créer car faux)

    Section corrected_s;
    corrected_s.name = ".rsrc";
    corrected_s.content = rsrc.content;
    corrected_s.virtualAddress = rsrc_virtualadress;
    corrected_s.virtualSize = rsrc_virtualsize;
    corrected_s.sizeOfRawData = pb.get_section(3).sizeOfRawData;
    corrected_s.pointerToRawData = pb.get_section(3).pointerToRawData;
    corrected_s.characteristics = 0x40000040;

    pb.replace_section(3, corrected_s);

    // Re-layout après correction
    pb.layout();

    // Fixe la rsrc directory import
    pb.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, rsrc_virtualadress, pb.get_section(3).sizeOfRawData); //écrire dans la table de directory du PE la section


    // RVAs et VAs utiles
    u32 text_rva = pb.text().virtualAddress;
    u32 msg1_rva = pb.get_data_rva(2, msg1_offset);   // section index 2 == .data (comme dans ton code)
    u32 msg2_rva = pb.get_data_rva(2, msg2_offset);
    u32 done_msg_rva = pb.get_data_rva(2, done_msg_offset);
    u32 msg_label_rva = pb.get_data_rva(2, msg_label_offset); //chaine fixe de texte au dessus du edit
    u32 msg_prefix_rva = pb.get_data_rva(2, msg_prefix_offset); //chaine fixe de texte dans le edit
    u32 entry_buf_w_rva = pb.get_data_rva(2, entry_buf_w_offset); //emplacement de l'écriture de la valeur id pressed (entry en wchar_t utf-16)
    u32 entry_buf_a_rva = pb.get_data_rva(2, entry_buf_a_offset); //emplacement de l'écriture de la valeur id pressed (entry en char ascii)
    u32 buffer_adr_rva = pb.get_data_rva(2,buf_adr_offset);     //buffer qui stock l'adresse du début du texte à afficher

    u64 msg1_va = IMAGE_BASE + static_cast<u64>(msg1_rva);
    u64 msg2_va = IMAGE_BASE + static_cast<u64>(msg2_rva);
    u64 done_msg_va = IMAGE_BASE + static_cast<u64>(done_msg_rva);
    u64 msg_label_va = IMAGE_BASE + static_cast<u64>(msg_label_rva);
    u64 msg_prefix_va = IMAGE_BASE + static_cast<u64>(msg_prefix_rva);
    u64 entry_buf_w_va = IMAGE_BASE + static_cast<u64>(entry_buf_w_rva);
    u64 entry_buf_a_va = IMAGE_BASE + static_cast<u64>(entry_buf_a_rva);
    u64 buffer_adr_va = IMAGE_BASE + static_cast<u64>(buffer_adr_rva);

    // IAT entries (VA of the IAT slot) -> image base + RVA returned by idata.get_import_rva()
    u64 printf_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf", idata_virtualadress));
    u64 puts_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("msvcrt.dll", "puts",   idata_virtualadress));
    u64 create_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "CreateThread", idata_virtualadress));
    u64 wait_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "WaitForSingleObject", idata_virtualadress));
    u64 exit_iat_va   = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess", idata_virtualadress));
    u64 lstrlenw_iat_va  = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "lstrlenW", idata_virtualadress));
    u64 dialogbox_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "DialogBoxParamW", idata_virtualadress));
    u64 enddialog_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "EndDialog", idata_virtualadress));
    u64 getmodule_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("kernel32.dll", "GetModuleHandleW", idata_virtualadress));
    u64 getdlgitemtext_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "GetDlgItemTextW", idata_virtualadress));
    u64 senddlgitemmsg_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("user32.dll", "SendDlgItemMessageW", idata_virtualadress));
    u64 elipse_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "Ellipse", idata_virtualadress));
    u64 rectangle_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "Rectangle", idata_virtualadress));
    u64 textoutw_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "TextOutW", idata_virtualadress));
    u64 settextcolor_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "SetTextColor", idata_virtualadress));
    u64 setbkmode_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "SetBkMode", idata_virtualadress));
    u64 createsolidbrush_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "CreateSolidBrush", idata_virtualadress));
    u64 getstockobject_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "GetStockObject", idata_virtualadress));
    u64 selectobject_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "SelectObject", idata_virtualadress));
    u64 deleteobject_iat_va = IMAGE_BASE + static_cast<u64>(idata.get_import_rva("gdi32.dll", "DeleteObject", idata_virtualadress));


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

    "mov rax, " + to_string(senddlgitemmsg_iat_va) + "\n"
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

    "mov rax, " + to_string(msg_prefix_va) + "\n"         // wchar_t* du placeholder (texte de l'EDIT en arrière plan)
    "mov [rsp+20h], rax\n"           // LPARAM sur la stack

    "mov rax, " + to_string(senddlgitemmsg_iat_va) + "\n"
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
    "mov r8, " + to_string(entry_buf_w_va) + "\n" // buffer wchar_t VA fourni pour stocker le texte (taille 512 car en char mais donner 256)
    "mov r9d, 256\n"             // taille max du buffer
    "mov rax, " + to_string(getdlgitemtext_iat_va) + "\n" // GetDlgItemTextW
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "mov rcx, rdi\n"            // hwnd restoration depuis rdi
    "xor edx, edx\n"

    "jmp .convertion_func\n"    //aller au code de conversion
    ".return_convertion_func:\n"  //retour du code de conversion

    "mov rax, " + to_string(entry_buf_a_va) + "\n"
    "mov rdx, " + to_string(buffer_adr_va) + "\n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire (donc le texte en ascii)
    "jmp .end_command\n"

    ".cancel:\n"
    "mov rax, "+ to_string(msg1_va) + "\n"
    "mov rdx, " + to_string(buffer_adr_va) + "\n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire
    "jmp .end_command\n"

    ".closed:\n"
    "mov rax, " + to_string(msg2_va) + "\n"
    "mov rdx, " + to_string(buffer_adr_va) + "\n"
    "mov [rdx], rax\n" //écrire dans le buffer prédéfinit l'adresse du texte à lire
    "jmp .end_command\n"

    ".end_command:\n"
    "mov eax, 1\n" //dire à DialogBoxParam que WM_COMMAND est traité
    "sub rsp, 28h\n"
    "mov rbx, rax\n"
    "mov rax, " + to_string(enddialog_iat_va) + "\n"
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
    "mov rax, " + to_string(createsolidbrush_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rsi, rax\n"      // sauvegarde HBRUSH
    "add rsp, 28h\n"

    //selectionne le HBRUSH creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rsi\n"        // HBRUSH creer
    "mov rax," + to_string(selectobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rdi, rax\n"        // sauvegarde ancien brush
    "add rsp, 28h\n"

    //creer un null_pen
    "sub rsp, 28h\n"
    "mov ecx, 8\n"                // NULL_PEN = 8 dans GetStockObject
    "mov rax, " + to_string(getstockobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov r11, rax\n"              // sauvegarde le stylo nul
    "add rsp, 28h\n"

    //selectionne le null_pen creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, r11\n"        // null_pen creer
    "mov rax," + to_string(selectobject_iat_va) + "\n"
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
    "mov rax, " + to_string(rectangle_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"


    //selectionne le pen d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, r10\n"        // retstorer l'ancien stylo
    "mov rax," + to_string(selectobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne le HBRUSH d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rdi\n"        // retstorer l'ancien brush
    "mov rax," + to_string(selectobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // nettoyer le HBRUSH creer stocker sur rsi
    "mov rcx, rsi\n"
    "mov rax, " + to_string(deleteobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne la couleur du texte
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"              // HDC
    "mov edx, 0x000000\n"         // noir
    "mov rax, " + to_string(settextcolor_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //fond transparent
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"             // HDC
    "mov edx, 1\n"               // TRANSPARENT
    "mov rax, " + to_string(setbkmode_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //calculer la longueur exacte de la chaîne pour afficher le texte avec lstrlenW
    "sub rsp, 28h\n"
    "mov rcx, " + to_string(msg_label_va) + "\n"
    "mov rax, " + to_string(lstrlenw_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"
    //reponse dans rax, pas besoin de le bouger vu que appeller après

    //texte du label mais avec le font correct pas comme si on le met dans rt_dialog LABEL (même position)
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"               // HDC
    "mov rdx, 0x30\n"              // x
    "mov r8, 0x35\n"              // y
    "mov r9, " + to_string(msg_label_va) + "\n"     // texte UTF-16
    "mov qword ptr [rsp+20h], rax\n" // c  (longueur exacte de la chaine)
    "mov rax, " + to_string(textoutw_iat_va) + "\n"
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
    "mov rax, " + to_string(createsolidbrush_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "mov rsi, rax\n"      // sauvegarde HBRUSH
    "add rsp, 28h\n"

    //selectionne le HBRUSH creer
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rsi\n"        // HBRUSH creer (bleu)
    "mov rax," + to_string(selectobject_iat_va) + "\n"
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
    "mov rax, " + to_string(elipse_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    //selectionne le HBRUSH d'origine
    "sub rsp, 28h\n"
    "mov rcx, rbx\n"        // HDC
    "mov rdx, rdi\n"        // retstorer l'ancien brush
    "mov rax," + to_string(selectobject_iat_va) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // nettoyer le HBRUSH creer stocker sur rsi
    "mov rcx, rsi\n"
    "mov rax, " + to_string(deleteobject_iat_va) + "\n"
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
    "mov rsi, " + to_string(entry_buf_w_va) + "\n"           // source UTF-16
    "mov rdi, " + to_string(entry_buf_a_va) + "\n"     // destination ASCII

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

    // Assemble thread function into bytes
    vector<u8> dialog_proc_bytes = assemble(dialog_proc_asm.c_str());

    // --- 2) MAIN code that creates the thread, waits, prints final message and exit ---
    // Compute thread start VA (it will be at start of .text section)
    u64 dialog_proc_va = IMAGE_BASE + static_cast<u64>(pb.text().virtualAddress); // because we will put thread first
    // Note: main entry will be placed right after thread_bytes in .text content

    // Main assembly: create thread, wait for it, then printf("Terminé\n"), ExitProcess(0)
    // We'll allocate a 64 bytes stack frame for shadow space and extra 5/6th args.
    string main_asm =
        // prologue for main - reserve shadow + extra stack space
        "sub rsp, 28h\n"

        // hInstance = GetModuleHandleW(NULL)
        "xor rcx, rcx\n"
        "mov rax, " + to_string(getmodule_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // DialogBoxParamW(hInst, ID=1, NULL, dialog_proc, 0)
        "mov rcx, rax\n"                        // hInstance
        "mov rdx, 4\n"                          // MAKEINTRESOURCEW(4)   (on a donné comme id 4 la rt_dialog)
        "xor r8, r8\n"                          // parent = NULL
        "mov r9, " + to_string(dialog_proc_va) + "\n"

        "mov qword ptr [rsp+20h], 0\n"

        "mov rax, " + to_string(dialogbox_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        "mov rbx, "+ to_string(buffer_adr_va) + "\n"  //récupère l'adresse de la réponse dialog dans le buffer

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // Print final message: puts("Terminé\n")
        "mov rcx, " + to_string(done_msg_va) + "\n"
        "mov rax, " + to_string(puts_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // appeler puts (affiche message) keystone ne comprend pas donc ignore et cut en 2 main alors que c'est la suite
        "mov rax, [rbx]\n"  //reprend la réponse (adresse de rbx)
        "mov rcx, rax\n"
        "mov rax," + to_string(puts_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"

        // After wait, free stack reserved earlier
        "add rsp, 28h\n"
        "sub rsp, 28h\n"

        // ExitProcess(0)
        "xor ecx, ecx\n"
        "mov rax, " + to_string(exit_iat_va) + "\n"
        "mov rax, [rax]\n"
        "call rax\n"
        "ret\n"

        //terminer au dessus
        ;

    // Assemble main1
    vector<u8> main_bytes = assemble(main_asm.c_str());

    // Build final .text content: dialog_bytes followed by main_bytes
    vector<u8> final_text;
    final_text.insert(final_text.end(), dialog_proc_bytes.begin(), dialog_proc_bytes.end());
    final_text.insert(final_text.end(), main_bytes.begin(), main_bytes.end());


    // Optionally pad to maintain alignment (not strictly required here)
    pb.text().content = final_text;

    // Debug print
    print_hex(pb.text().content);

    // Construit le PE avec l'entry point = pb.text().virtualAddress + offset where main starts
    size_t entry_rva_ = pb.text().virtualAddress + dialog_proc_bytes.size() + 0; // optionally +32 for extra NOP if you want
    vector<u8> pe = pb.build(entry_rva_);

    // write file
    HANDLE f = CreateFileA("out_dialog.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    // show sections and debug info as you had
    pb.see_section();

    std::cout << "Thread start VA: " << std::hex << dialog_proc_va << std::endl;
    std::cout << "entry_rva (main) : " << std::hex << entry_rva_ << std::endl;
    std::cout << "printf_iat_va: " << std::hex << printf_iat_va << std::endl;
    std::cout << "create_iat_va: " << std::hex << create_iat_va << std::endl;
    std::cout << "wait_iat_va: " << std::hex << wait_iat_va << std::endl;
    std::cout << "exit_iat_va: " << std::hex << exit_iat_va << std::endl;

    return 0;
}*/

//exemple 6

/*
//gestion des exception avec addvectorexceptionhandler (exception fait volontairement, mais intercepte toutes les exceptions) (reprise du premier code mais plus structurer avec des call )
//erreur avec printf exemple
int main() {
    IDATA idata;
    idata.add_import("msvcrt.dll", {"printf", "fflush"});
    idata.add_import("kernel32.dll", {"RaiseException", "ExitProcess", "AddVectoredExceptionHandler"});

    // Prépare la section .idata //layout() automatique respecte les sections
    idata.prepare();


    PEBuilder pb; //créer la section text en premier

    // Récupère le contenu de la section .idata
    std::vector<u8> idata_content = idata.get_content();

    // Ajoute la section .idata à votre PEBuilder
    Section idata_section;
    idata_section.name = ".idata";
    idata_section.content = idata_content;
    idata_section.virtualAddress = 0x0;
    idata_section.virtualSize = idata.get_size();
    idata_section.sizeOfRawData = idata.get_size();
    idata_section.characteristics = 0xC0000040; // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
    pb.push_section(idata_section);

    pb.layout(); //initialiser les adresses

    //refaire avec les vrai adresses absolu
    u32 idata_virtualadress = pb.get_section(1).virtualAddress;
    u32 idata_virtualsize = pb.get_section(1).virtualSize;

    idata.reprepare(idata_virtualadress); //refaire avec adresse absolu

     Section corrected_idata_section;
    corrected_idata_section.name = ".idata";
    corrected_idata_section.content = idata.get_content();
    corrected_idata_section.virtualAddress = idata_virtualadress;
    corrected_idata_section.virtualSize = idata_virtualsize;
    corrected_idata_section.sizeOfRawData = pb.get_section(1).sizeOfRawData;
    corrected_idata_section.pointerToRawData = pb.get_section(1).pointerToRawData;
    corrected_idata_section.characteristics = 0xC0000040;

    pb.replace_section(1, corrected_idata_section);

    pb.layout(); //initialiser les adresses

    pb.set_data_directory(1, idata_virtualadress, pb.get_section(1).sizeOfRawData); //mettre idata dans le tableau de chargement windows

    // Ajoute des données dans une section dédiée
    Section& dataSection = pb.add_custom_section(".data", 0xC0000040);
    dataSection.content={}; //vide sinon valeur automatique 0x90 *4
    const char msg[] = "Hello World\n\0";
    size_t msg_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg, msg + sizeof(msg));
    const char msg_e[] = "Error 0xXXXXXXXX !\n\0";  //(les X sont remplacer par le code d'erreur afficher que l'on a mi dans raiseexception)
    size_t msg_e_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), msg_e, msg_e + sizeof(msg_e));
    const char buffer_addr_exception[40] = {0};
    size_t buffer_addr_exception_offset = dataSection.content.size();
    dataSection.content.insert(dataSection.content.end(), buffer_addr_exception, buffer_addr_exception + sizeof(buffer_addr_exception));

    // Calcule les adresses virtuelles et physiques des sections
    pb.layout();

    // Code assembleur
    u32 text_rva = pb.text().virtualAddress;
    u32 msg_rva = pb.get_data_rva(2, msg_offset); // 2 est l'index de la section .data
    u32 msg_e_rva = pb.get_data_rva(2,msg_e_offset);
    u32 buffer_addr_exception_rva = pb.get_data_rva(2,buffer_addr_exception_offset);
    u64 printf_rva = static_cast<u64>(idata.get_import_rva("msvcrt.dll", "printf",idata_virtualadress))+IMAGE_BASE;
    u64 fflush_rva = static_cast<u64>(idata.get_import_rva("msvcrt.dll", "fflush",idata_virtualadress))+IMAGE_BASE;
    u64 exit_rva = static_cast<u64>(idata.get_import_rva("kernel32.dll", "ExitProcess",idata_virtualadress))+IMAGE_BASE;
    u64 raiseexception_rva = static_cast<u64>(idata.get_import_rva("kernel32.dll", "RaiseException",idata_virtualadress))+IMAGE_BASE;
    u64 addveh_rva = static_cast<u64>(idata.get_import_rva("kernel32.dll", "AddVectoredExceptionHandler",idata_virtualadress))+IMAGE_BASE;

    u64 msg_va = IMAGE_BASE + static_cast<u64>(msg_rva); //conversion va machine avec l'image base
    u64 msg_e_va = IMAGE_BASE + static_cast<u64>(msg_e_rva); //conversion va machine avec l'image base
    u64 buffer_addr_exception_va = IMAGE_BASE + static_cast<u64>(buffer_addr_exception_rva); //conversion va machine avec l'image base


    string asm_code_error =
    // RCX = EXCEPTION_POINTERS*
    "mov rax, [rcx+8]\n"       // CONTEXT*

    //charger le buffer de restauration pile et adresse en cas d'exception
    "mov rsi, " + to_string(buffer_addr_exception_va) + "\n"

    //mettre control dans contextflag
    "mov edx, "+to_string(CONTEXT_FULL)+"\n" //CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS
    "mov dword ptr [rax+30h], edx\n"

    //restorer mxcsr valeur par defaut
    "mov edx, 0x1F80\n"
    "mov dword ptr [rax+34h], edx\n"

    //restorer rflags valeur par defaut
    "mov rdx, 0x244\n"
    "mov [rax+44h], rdx\n"

    // restaurer RSP
    "mov rdx, [rsi+12]\n"
    "mov [rax+98h], rdx\n"

    // changer RIP
    "mov rdx, [rsi]\n"
    "mov [rax+0F8h], rdx\n" //renvoyé rip sur l'adresse de début du buffer pour rip

    //nettoye registre à 0
    "xor rdx, rdx\n"
    //nettoye registre debug
    "mov [rax+048h], rdx\n"       // Dr0
    "mov [rax+050h], rdx\n"       // Dr1
    "mov [rax+058h], rdx\n"       // Dr2
    "mov [rax+060h], rdx\n"       // Dr3
    "mov [rax+068h], rdx\n"       // Dr6
    "mov [rax+070h], rdx\n"       // Dr7
    //nettoye registre volatile
    "mov [rax+078h], rdx\n"       // Rax
    "mov [rax+080h], rdx\n"       // Rcx
    "mov [rax+088h], rdx\n"       // Rdx
    "mov [rax+0B8h], rdx\n"       // R8
    "mov [rax+0C0h], rdx\n"       // R9
    "mov [rax+0C8h], rdx\n"       // R10
    "mov [rax+0D0h], rdx\n"       // R11

    // vider XMM0 -> XMM15
    "pxor xmm15, xmm15\n"  //(xmm15 n'est pas utiliser dans mon teste donc ça ne casse pas le handler)
    "movdqa [rax+1A0h], xmm15\n"
    "movdqa [rax+1B0h], xmm15\n"
    "movdqa [rax+1C0h], xmm15\n"
    "movdqa [rax+1D0h], xmm15\n"
    "movdqa [rax+1E0h], xmm15\n"
    "movdqa [rax+1F0h], xmm15\n"
    "movdqa [rax+200h], xmm15\n"
    "movdqa [rax+210h], xmm15\n"
    "movdqa [rax+220h], xmm15\n"
    "movdqa [rax+230h], xmm15\n"
    "movdqa [rax+240h], xmm15\n"
    "movdqa [rax+250h], xmm15\n"
    "movdqa [rax+260h], xmm15\n"
    "movdqa [rax+270h], xmm15\n"
    "movdqa [rax+280h], xmm15\n"
    "movdqa [rax+290h], xmm15\n"

    //optionnel renvoie dans buffer d'exception le code d'erreur à la position 8
    "mov rax, [rcx]\n"  //EXCEPTION_RECORD
    "mov edx, [rax]\n"  //bas de rdx en dword
    "mov [rsi+8], edx\n" //copier dans le buffer d'exception à +8 les 4 octets d'exception
    //fin optionnel

    "mov eax, "+to_string(EXCEPTION_CONTINUE_EXECUTION)+"\n"   //EXCEPTION_CONTINUE_EXECUTION=-1
    "ret\n"
    "nop\n";

    pb.text().content = assemble(asm_code_error.c_str());

    std::cout << "1" << std::endl;

    u32 size_executable_error = text_rva + static_cast<u32>(pb.text().content.size());

    string asm_code1 =
    "sub rsp, 28h\n"
    "mov rcx, 1\n"   // First = priorité max
    "mov rdx, " + to_string(text_rva+IMAGE_BASE) + "\n" // adresse du handler (asm_code_error)
    "mov rax, " + to_string(addveh_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"
    "ret\n"
    "nop\n"
    ;

    vector<u8> asm_code_vec = assemble(asm_code1.c_str());
    pb.text().content.insert(pb.text().content.end(), asm_code_vec.begin(), asm_code_vec.end());

    std::cout << "2" << std::endl;

    u32 size_executable_1 = text_rva + static_cast<u32>(pb.text().content.size());

    string asm_code2 =
    "sub rsp, 28h\n"                                      // align stack (Windows x64)
    "mov rcx, " + to_string(msg_va) + "\n"                // RCX = ptr vers la chaîne (arg1 pour printf)
    // --- appeler printf via son IAT ---
    "mov rax, " + to_string(printf_rva) + "\n"         // RAX = adresse de l'entrée IAT (pointer vers l'adresse de la fonction)
    "mov rax, [rax]\n"                                    // RAX = valeur contenue dans l'IAT (adresse réelle de printf)
    "call rax\n"                                          // call printf
    "add rsp, 28h\n"
    "ret\n"
    "nop\n";

    asm_code_vec = assemble(asm_code2.c_str());
    pb.text().content.insert(pb.text().content.end(), asm_code_vec.begin(), asm_code_vec.end());

    std::cout << "3" << std::endl;

    u32 size_executable_2 = text_rva + static_cast<u32>(pb.text().content.size());

    string asm_code3 =
    "sub rsp, 30h\n"

    //"int 2Eh\n"

    // --- préparer une exception fatale ---
    //"mov ecx, 0C0000005h\n"   // ExceptionCode classique
    "mov ecx, 0E0000001h\n"     //ExceptionCode différent inventer
    "xor edx, edx\n"          // Flags
    "xor r8d, r8d\n"          // NumberParameters
    "xor r9d, r9d\n"
    "mov rax, " + to_string(raiseexception_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 30h\n"
    "ret\n"
    "nop\n";

    asm_code_vec = assemble(asm_code3.c_str());
    pb.text().content.insert(pb.text().content.end(), asm_code_vec.begin(), asm_code_vec.end());

    std::cout << "4" << std::endl;

    u32 size_executable_3 = text_rva + static_cast<u32>(pb.text().content.size());

    string asm_msg_error =
    // rdi = ExceptionCode
    "mov rdi, " + to_string(buffer_addr_exception_va+8) + "\n" //+8 car le code dans le handler écrit à cette endroit entre  rip (0) et rsp (+12)
    "mov rdi, [rdi]\n"

    "mov rsi, " + to_string(msg_e_va + 8) + "\n"
    "mov eax, edi\n"
    "mov ecx, 8\n"

    ".hex_loop:\n"
    "mov edx, eax\n"
    "shr edx, 28\n"
    "and edx, 0Fh\n"
    "cmp edx, 9\n"
    "jbe .digit\n"
    "add edx, 37h\n"        // 'A' - 10
    "jmp .store\n"
    ".digit:\n"
    "add edx, 30h\n"
    ".store:\n"
    "mov [rsi], dl\n"
    "inc rsi\n"
    "shl eax, 4\n"
    "loop .hex_loop\n"

    "sub rsp, 28h\n"
    "mov rcx, " + to_string(msg_e_va) + "\n" //message d'error
    // --- appeler printf via son IAT ---
    "mov rax, " + to_string(printf_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    // Forcer le vidage du tampon (fflush)
    "sub rsp, 28h\n"
    "mov rcx, 0\n" // 0 = stdout
    "mov rax, " + to_string(fflush_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"

    "sub rsp, 28h\n"
    // ExitProcess(0)
    "xor ecx, ecx\n"
    "mov rax, " + to_string(exit_rva) + "\n"
    "mov rax, [rax]\n"
    "call rax\n"
    "add rsp, 28h\n"
    "ret\n"
    "nop\n";

    asm_code_vec = assemble(asm_msg_error.c_str());
    pb.text().content.insert(pb.text().content.end(), asm_code_vec.begin(), asm_code_vec.end());

    std::cout << "5" << std::endl;

    u32 size_executable_4 = text_rva + static_cast<u32>(pb.text().content.size());

    u32 addr_entry_point = size_executable_4; //adresse du debut de la fonction principal

    string asm_code_entry_point =
    //sauvgarde l'addresse de l'exception
    "mov rdi, " + to_string(buffer_addr_exception_va) + "\n"
    "mov rsi, " + to_string(size_executable_3+IMAGE_BASE) + "\n"
    "mov [rdi], rsi\n"
    // sauvegarder RSP ACTUEL initial sans erreur pour pouvoir restorer la pile proprement avant une exception
    "mov rsi, rsp\n"
    "mov [rdi+12], rsi\n"

    "mov rax, " + to_string(size_executable_error+IMAGE_BASE) + "\n" //fonction 1
    "call rax\n"
    "mov rax, " + to_string(size_executable_1+IMAGE_BASE) + "\n" //fonction 2
    "call rax\n"
    "mov rax, " + to_string(size_executable_2+IMAGE_BASE) + "\n" //fonction 3
    "call rax\n"
    "ret\n"
    "nop\n"; //fin

    asm_code_vec = assemble(asm_code_entry_point.c_str());
    pb.text().content.insert(pb.text().content.end(), asm_code_vec.begin(), asm_code_vec.end());

    //std::cout << "Taille du code assemble 6 : " << asm_code_vec.size() << std::endl;
    std::cout << "6" << std::endl;

    print_hex(pb.text().content);

    // Construit le PE
    vector<u8> pe = pb.build(size_t(addr_entry_point));

    // Écrit le fichier
    HANDLE f = CreateFileA("out_error.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
    CloseHandle(f);

    pb.see_section();

    std::cout << "RVA de printf : " << std::hex << printf_rva << std::endl;
    std::cout << "RVA de ExitProcess : " << std::hex << exit_rva << std::endl;

    return 0;
}
*/
