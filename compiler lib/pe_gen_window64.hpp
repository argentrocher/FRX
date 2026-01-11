/*
PE BUILDER BY ARGENTROPCHER (ASSIGNE AU COMPTE GOOGLE ARGENTROPCHER)

Si vous utiliser ce code, il est seulement obligatoire de citer que vous utiliser "keystone" pour l'assembleur si vous utiliser les exemples et de citer ce depot "github" ou "BY ARGENTROPCHER".
PS : merci à "keystone" pour sont assembleur sinon, ecrire les bit à la main est impossible.

ce code est testé avec mingw g++, et est censer être compatible avec msvsc.

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
#include <unordered_map>
#include <functional>
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


using namespace std;
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;


#ifndef PE_CONST
#define PE_CONST
constexpr u32 FILE_ALIGNMENT = 0x200;
constexpr u32 SECTION_ALIGNMENT = 0x1000;
constexpr u64 IMAGE_BASE = 0x4000000; //0x140000000ULL;
#endif // PE_CONST

#ifndef IMAGE_CONST
#define IMAGE_CONST
constexpr u32 IMAGE_SCN_CNT_CODE_ = 0x20000000;
constexpr u32 IMAGE_SCN_MEM_READ_ = 0x40000000;
constexpr u32 IMAGE_SCN_MEM_WRITE_ = 0x80000000;
constexpr u32 IMAGE_SCN_MEM_EXECUTE_ = 0x20000000;
constexpr u32 IMAGE_SCN_CNT_INITIALIZED_DATA_ = 0x40000000;
#endif // IMAGE_CONST

static inline u64 align_up(u64 v, u64 a) { return (v + a - 1) & ~(a - 1); }

vector<u8> assemble(const char* code); //declaration de assemble pour TEXT

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

    vector<u8> build(u32 entry_rva, bool with_console=true) {
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
        if (with_console==true)
            push_u16(3); // Subsystem (CONSOLE)
        else
            push_u16(2); // GUI

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

    void prepare(u32 idata_rva=0) {
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
        return 0xFFFFFFFF; // Fonction non trouvée
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

    void push_manifest(const std::string& manifestContent) {
        // Convertir le contenu du manifest en un vecteur de bytes
        std::vector<u8> data(manifestContent.begin(), manifestContent.end());
        // Ajouter la ressource de type RT_MANIFEST avec l'ID 1
        add_resource(RT_MANIFEST_, 1, data);
    }


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
    void prepare(u32 rsrc_virtual_address=0)
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

class DATA {
public:
    std::vector<u8> content;       // contenu brut
    std::string name = ".data";
    u32 virtualAddress = 0;
    u32 virtualSize = 0;

    // stockage des offsets pour chaque élément
    std::map<std::string, size_t> offsets;

    // ajouter une chaîne ASCII (avec '\0')
    size_t add_ascii(const std::string& str, const std::string& key = "") {
        size_t offset = content.size();
        content.insert(content.end(), str.begin(), str.end());
        content.push_back(0); // null terminate
        if(!key.empty()) offsets[key] = offset;
        return offset;
    }

    // ajouter une chaîne UTF-16 (little-endian, null-terminated)
    size_t add_utf16(const std::wstring& str, const std::string& key = "") {
        size_t offset = content.size();
        for(wchar_t c : str) {
            content.push_back(c & 0xFF);
            content.push_back((c >> 8) & 0xFF);
        }
        content.push_back(0);
        content.push_back(0); // null terminate
        if(!key.empty()) offsets[key] = offset;
        return offset;
    }

    // ajouter un buffer vide de n octets
    size_t add_empty(size_t n, const std::string& key = "") {
        size_t offset = content.size();
        content.insert(content.end(), n, 0);
        if(!key.empty()) offsets[key] = offset;
        return offset;
    }

    // préparation : calculer RVA et taille virtuelle
    void prepare(u32 baseRVA) {
        virtualAddress = baseRVA;
        virtualSize = static_cast<u32>(content.size());
    }

    // récupérer RVA à partir de l'offset stocké
    u32 get_rva(const std::string& key, u32 virtual_addr = 0xFFFFFFFF) {
        if (virtual_addr == 0xFFFFFFFF) {
            if(offsets.find(key) != offsets.end()) {
                return virtualAddress + static_cast<u32>(offsets[key]);
            }
            return 0xFFFFFFFF; //pas trouver cette key
        } else {
            if(offsets.find(key) != offsets.end()) {
                return virtual_addr + static_cast<u32>(offsets[key]);
            }
            return 0xFFFFFFFF; //pas trouver cette key
        }
    }

    // récupérer VA (image base + RVA)
    u64 get_va(const std::string& key, u32 virtual_addr = 0xFFFFFFFF) {
        u32 result_of_get_rva = get_rva(key, virtual_addr);
        if (result_of_get_rva == 0xFFFFFFFF) return 0;
        return IMAGE_BASE + static_cast<u64>(result_of_get_rva);
    }
};

class TEXT {
public:
    struct AsmFunction {
        std::string name;
        std::string raw_code;
        std::vector<u8> assembled;
        u32 offset = 0; // offset dans .text
    };

private:
    std::vector<AsmFunction> functions;
    std::unordered_map<std::string, u32> symbol_table; // name -> RVA
    u32 base_rva = 0;

    // callback pour résoudre symboles externes (idata, data, etc.)
    std::function<u64(const std::string&)> external_resolver;

public:
    std::vector<u8> content;

    TEXT();

    void set_external_resolver(std::function<u64(const std::string&)> cb) {
        external_resolver = cb;
    }

    void add_function(const std::string& name, const std::string& asm_code) {
        AsmFunction f;
        f.name = name;
        f.raw_code = asm_code;
        functions.push_back(f);
    }

private:
    std::string resolve_symbols(const std::string& code, bool real) {
        std::string out;
        out.reserve(code.size());

        for (size_t i = 0; i < code.size(); ) {
            if (code[i] == '$') {
                i++;
                std::string name;
                while (i < code.size() && (isalnum(code[i]) || code[i] == '_')) {
                    name += code[i++];
                }

                u64 value = 0;

                if (real) {
                    // 1) fonction ASM interne
                    auto it = symbol_table.find(name);
                    if (it != symbol_table.end()) {
                        value = IMAGE_BASE + it->second;
                    }
                    // 2) externe (idata, data, etc.)
                    else if (external_resolver) {
                        value = external_resolver(name);
                    }
                }

                out += std::to_string(value);
            } else {
                out += code[i++];
            }
        }

        return out;
    }

public:
    void prepare(u32 text_rva) {
        base_rva = text_rva;
        content.clear();
        symbol_table.clear();

        // 1) première passe : calcul offsets
        u32 current_offset = 0;
        for (auto& f : functions) {
            f.offset = current_offset;

            // assembler avec $ remplacé par 0
            std::string safe_code = resolve_symbols(f.raw_code, false);
            f.assembled = assemble(safe_code.c_str());

            current_offset += static_cast<u32>(f.assembled.size());
        }

        // 2) construire table des symboles
        for (auto& f : functions) {
            symbol_table[f.name] = base_rva + f.offset;
        }

        // 3) deuxième passe : assembler avec vraies adresses
        content.clear();
        for (auto& f : functions) {
            std::string final_code = resolve_symbols(f.raw_code, true);
            f.assembled = assemble(final_code.c_str());
            content.insert(content.end(), f.assembled.begin(), f.assembled.end());
        }
    }

    u32 get_function_rva(const std::string& name) const {
        auto it = symbol_table.find(name);
        if (it == symbol_table.end()) return 0xFFFFFFFF;
        return it->second;
    }
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

struct SectionInfo {
    std::string name;
    u32 index;              // index dans le PEBuilder
    u32 virtualAddress;     // RVA après layout
    u32 virtualSize;        // taille virtuelle
    u32 sizeOfRawData;      // taille brute
    Section section;        // la section elle-même
};

//controlleur central, mieux simplifie le code
class GESTION {
private:
    std::vector<SectionInfo> sections; // structure pour stocker toutes les sections
    u32 section_index = 1; //car la première est text, c'est 0 mais automatique

    bool see_exception_not_fatal = false; //on ne voit pas les notification d'exception possible au moment du solver

    //.text est créer automatiquement par PEbuilder à ça création, on copie pour qu'il soit dans sectioninfo
    void create_section_text_in_sectioninfo() {
        pb.layout();

        Section s;
        SectionInfo info;

        info.name = ".text";
        info.index = 0; //0 est l'index de .text
        info.virtualAddress = pb.get_section(0).virtualAddress;
        info.virtualSize = pb.get_section(0).virtualSize;
        info.sizeOfRawData = pb.get_section(0).sizeOfRawData;
        s.name = ".text";
        s.content = pb.text().content;
        s.virtualAddress = info.virtualAddress;
        s.virtualSize = info.virtualSize;
        s.sizeOfRawData = pb.get_section(0).sizeOfRawData;
        s.pointerToRawData = pb.get_section(0).pointerToRawData;
        s.characteristics = 0x60000020; // CODE | EXECUTE | READ (emplacement du code à écrire par l'utilisateur)
        info.section = s;

        sections.push_back(info);
    }

    std::string name_exe="out.exe";
    bool is_console = true;
    u32 addr_entry_point;

    bool as_ico=false; //pas d'ico définit

    // Récupère le virtualAddress d'une section par son nom
    // Retourne 0 si la section n'est pas trouvée
    u32 get_section_virtual_address(const std::string& name) {
        for (const auto& section_ : sections) {
            if (section_.name == name) {
                return section_.virtualAddress; // Retourne le virtualAddress
            }
        }
        return 0xFFFFFFFF; // Section non trouvée
    }

    // Récupère le virtualAddress d'une section par son nom
    // Retourne 0 si la section n'est pas trouvée
    u32 get_section_index(const std::string& name) {
        for (const auto& section_ : sections) {
            if (section_.name == name) {
                return section_.index; // Retourne le virtualAddress
            }
        }
        return 0xFFFFFFFF; // Section non trouvée
    }

    bool as_this_section(const std::string& name) {
        for (const auto& section_ : sections) {
            if (section_.name == name) {
                return true;
            }
        }
        return false; // Section non trouvée
    }

public:
    //laisser l'accès au section public si l'utilisateur veux plus de fonctionnalité
    PEBuilder pb; //creer la section text automatiquement
    IDATA idata;
    DATA data;
    RSRC rsrc;
    TEXT asm_text;

    GESTION() {
        create_section_text_in_sectioninfo(); //appel à la fonction pour créer la configuration de text
    }
    // ---- GENERAL ----
    //changer le nom de l'exe
    void set_exe_name(const std::string& name) {
        name_exe=name;
    }
    //choisir si on veux la console cmd visible ou non
    void set_cmd(bool is_cmd) {
        is_console=is_cmd;
    }
    //définir le point d'entrer du code machine (généralement section text)
    void set_addr_entry_point(u32 addr_entry_code) {
        addr_entry_point = addr_entry_code;
    }
    //renvoie le nombre de section
    u32 get_num_section() {
        return section_index;
    }
    //permet de désactivé/activé les affichages d'exception non faltal à l'execution car ils peuvent être résolu plus tard
    void set_see_not_fatal_exception(bool see_exception_not_fatal_) {
        see_exception_not_fatal = see_exception_not_fatal_;
    }

    // ---- IMPORTS  IDATA----
    // Méthode générique pour ajouter des imports via idata
    void idata_add_imports(const std::vector<std::pair<std::string, std::vector<std::string>>>& imports) {
        for (auto& dll : imports) {
            const std::string& dll_name = dll.first;
            const std::vector<std::string>& funcs = dll.second;
            idata.add_import(dll_name, funcs);
        }
    }
    //pour récupérer l'adresse d'une function importer pour le code asm
    u64 get_idata_va(const std::string& dll_name_, const std::string& func_name_) {
        u32 reponse = get_section_virtual_address(".idata");
        if (reponse == 0xFFFFFFFF) {
            std::cout << "la section idata n'est pas encore creer avec push_section(\".idata\") ! \nopération impossible" << std::endl;
            return 0;
        }
        reponse = idata.get_import_rva(dll_name_, func_name_, reponse);
        if (reponse == 0xFFFFFFFF) {
            if (see_exception_not_fatal) {
                std::cout << "la fonction ou la dll n'a pas encore été importée avec idata_add_imports() !" << std::endl;
            }
            return 0;
        }
        return IMAGE_BASE + static_cast<u64>(reponse);
    }


    // ---- DATA ----
    size_t data_add_ascii(const std::string& str, const std::string& key = "") {
        return data.add_ascii(str,key);
    }
    size_t data_add_utf16(const std::wstring& str, const std::string& key = "") {
        return data.add_utf16(str,key);
    }
    size_t data_add_buffer(size_t n, const std::string& key = "") {
        return data.add_empty(n,key);
    }
    //renvoie l'adresse d'une chaine fixe pour autre chose que du code asm (car pas de image_base)
    u64 get_data_rva(const std::string& key){
        u32 reponse = get_section_virtual_address(".data");
        if (reponse == 0xFFFFFFFF) {
            std::cout << "la section data n'est pas encore creer avec push_section(\".data\") ! \nopération impossible" << std::endl;
            return 0;
        }
        reponse = data.get_rva(key, reponse);
        if (reponse == 0xFFFFFFFF) {
            if (see_exception_not_fatal) {
                std::cout << "clé recherché introuvable, doit être créer avec une fonction data_add...(string,key)" << std::endl;
            }
            return 0;
        }
        return reponse;
    }
    //renvoie l'addresse d'une chaine fixe pour le code asm (avec image_base inclu)
    u64 get_data_va(const std::string& key){
        u32 reponse = get_section_virtual_address(".data");
        if (reponse == 0xFFFFFFFF) {
            std::cout << "la section data n'est pas encore creer avec push_section(\".data\") ! \nopération impossible" << std::endl;
            return 0;
        }
        u64 reponse2 = data.get_va(key, reponse);
        if (reponse2 == 0) {
            if (see_exception_not_fatal) {
                std::cout << "clé recherché introuvable, doit être créer avec une fonction data_add...(string,key)" << std::endl;
            }
            return 0;
        }
        return reponse2;
    }

    // ---- RESOURCES ----
    //icon de l'exe
    void rsrc_create_exe_icon(const std::string& ico_path){
        if (as_ico) {
            std::cout << "il y a déjà un icon définit !" << std::endl;
            return;
        }
        DWORD attrib = GetFileAttributesA(ico_path.c_str());
        if (attrib == INVALID_FILE_ATTRIBUTES || (attrib & FILE_ATTRIBUTE_DIRECTORY)) {
            std::cout << "Le fichier " << ico_path << " n'existe pas." << std::endl;
            return;
        }
        rsrc.add_icon_from_file(ico_path);
        as_ico=true;
    }
    //version visible dans détail sur windows (complet)
    void rsrc_create_version(const std::wstring& fileVersion,
        const std::wstring& productVersion,
        const std::wstring& companyName,
        const std::wstring& fileDescription,
        const std::wstring& productName,
        const std::wstring& originalFilename,
        const std::wstring& copyright) {
        rsrc.add_version_full(fileVersion, productVersion, companyName, fileDescription, productName, originalFilename, copyright);
    }
    //version visible dans détail sur windows (simple)
    void rsrc_create_version_simple(const std::wstring& fileVersion = L"1.0.0.0", const std::wstring& exeName = L"out.exe", const std::wstring& copyright = L"argentropcher") {
        rsrc.add_version_full(fileVersion, fileVersion, L"PE_GEN_WINDOW64", L"exe 64 bits Windows", exeName, exeName, copyright);
    }
    //manifest xml a fournir pour créer dans rsrc celui-ci
    void rsrc_create_manifest(const std::string& manifestContent) {
        rsrc.push_manifest(manifestContent);
    }
    //manifest pour certaines fonctionnalité windows, droit administrateurs ... (tout fait)
    void rsrc_create_manifest_simple(const std::string& exeName = "out.exe",
        const std::string& version = "1.0.0.0",
        bool dpiAware = true,
        bool perMonitorV2 = true,
        bool requireAdmin = false,
        bool commonControlsV6 = false) {
        rsrc.add_manifest(exeName, version, dpiAware, perMonitorV2, requireAdmin, commonControlsV6); //manifest pour la sécurité et conformité windows (2 preimer bool= GUI affichage, 3 bool= admin nécessaire ou non 4 bool commonControlsV6 pour certaines fonctions de code asm qui utilise rt_dialog)
    }
    //creer un dialog (fournir avec la structure RSRC::DialogDesc) , lang paramètre suplémentaire d'information pays encodage
    void rsrc_create_dialog(const RSRC::DialogDesc& dsc, u16 lang = 0x0409) {
        rsrc.add_dialog(dsc,lang);
    }

    // ---- ASM ----
    void text_add_function(const std::string& name, const std::string& asm_code) {
        asm_text.add_function(name,asm_code);
    }
    u64 get_text_va(const std::string& name) {
        u32 reponse = asm_text.get_function_rva(name);
        if (reponse == 0xFFFFFFFF) {
            if (see_exception_not_fatal) {
                std::cout << "la fonction n'a pas été résolu ou n'existe pas !" << std::endl;
            }
            return 0;
        }
        return IMAGE_BASE + static_cast<u64>(reponse);
    }
    u32 get_text_rva(const std::string& name) {
        u32 reponse = asm_text.get_function_rva(name);
        if (reponse == 0xFFFFFFFF) {
            if (see_exception_not_fatal) {
                std::cout << "la fonction n'a pas été résolu ou n'existe pas !" << std::endl;
            }
            return 0;
        }
        return reponse;
    }
    void set_text_external_resolver(std::function<u64(const std::string&)> cb) {
        asm_text.set_external_resolver(cb);
    }


    // ---- PROCESSUS ----
    // Push automatique et enregistrement des sections
    void push_section(std::string type) {
        // ajouter le '.' si pas présent
        if (!type.empty() && type[0] != '.') {
            type = "." + type;
        }

        Section s;
        SectionInfo info;
        u32 this_index = 0;
        if (!as_this_section(type)) {
            info.index = section_index;
            this_index = section_index;
        } else {
            this_index = get_section_index(type);
            if (this_index == 0xFFFFFFFF) {
                std::cout << "erreur système !" << std::endl;
                return;
            }
            info.index = this_index;
        }

        if (type == ".idata") {
            idata.prepare(0x0); // adresse inconnue pour l'instant

            if (idata.get_size()==0) {
                std::cout << "erreur : idata est vide !" << std::endl;
                return;
            }

            s.name = ".idata";
            s.content = idata.get_content();
            s.virtualAddress = 0x0;
            s.virtualSize = idata.get_size();
            s.sizeOfRawData = idata.get_size();
            s.characteristics = 0xC0000040; // READ | WRITE | INITIALIZED_DATA

            if (!as_this_section(type)) {
                pb.push_section(s);
            } else {
                pb.replace_section(this_index, s);
            }
            pb.layout(); // Layout initial pour connaître RVA

            // récupérer les infos après layout
            info.name = s.name;
            info.virtualAddress = pb.get_section(this_index).virtualAddress;
            info.virtualSize = pb.get_section(this_index).virtualSize;
            info.sizeOfRawData = pb.get_section(this_index).sizeOfRawData;

            // refaire idata avec la vraie RVA
            idata.prepare(info.virtualAddress);

            // corriger la section
            s.name = ".idata";
            s.content = idata.get_content();
            s.virtualAddress = info.virtualAddress;
            s.virtualSize = info.virtualSize;
            s.sizeOfRawData = pb.get_section(this_index).sizeOfRawData;
            s.pointerToRawData = pb.get_section(this_index).pointerToRawData;
            s.characteristics = 0xC0000040;

            pb.replace_section(this_index, s);
            pb.layout(); // re-layout final

            // set data directory import
            pb.set_data_directory(1, info.virtualAddress, s.sizeOfRawData);

            info.section = s;
        }
        else if (type == ".data") {
            if (data.content.size()==0) {
                std::cout << "erreur : data est vide !" << std::endl;
                return;
            }

            s.name = ".data";
            s.content = data.content;
            s.virtualAddress = 0x0;
            s.virtualSize = data.content.size();
            s.sizeOfRawData = data.content.size();
            s.characteristics = 0xC0000040; // READ | WRITE

            if (!as_this_section(type)) {
                pb.push_section(s);
            } else {
                pb.replace_section(this_index, s);
            }
            pb.layout(); // Layout initial pour connaître RVA

            info.name = s.name;
            info.virtualAddress = pb.get_section(this_index).virtualAddress;
            info.virtualSize = pb.get_section(this_index).virtualSize;
            info.sizeOfRawData = pb.get_section(this_index).sizeOfRawData;

            data.prepare(info.virtualAddress);

            // corriger la section
            s.name = ".data";
            s.content = data.content;
            s.virtualAddress = info.virtualAddress;
            s.virtualSize = info.virtualSize;
            s.sizeOfRawData = info.sizeOfRawData;
            s.pointerToRawData = pb.get_section(this_index).pointerToRawData;
            s.characteristics = 0xC0000040; // READ | WRITE

            pb.replace_section(this_index, s);
            pb.layout(); // re-layout final

            info.section = s;
        }
        else if (type == ".text") {
            asm_text.prepare(0x0); //preparer adresse 0 pour savoir si il y a du comptenu

            if (asm_text.content.size()==0) {
                std::cout << "erreur : text est vide !" << std::endl;
                return;
            }
            this_index = 0 ; //text est toujours index 0 car créer obligatoirement par PEBuilder

            s.name = ".text";
            s.content = asm_text.content;
            s.virtualAddress = 0x0;
            s.virtualSize = asm_text.content.size();
            s.sizeOfRawData = asm_text.content.size();
            s.characteristics = 0x60000020; // CODE | EXECUTE | READ (emplacement du code à écrire par l'utilisateur)

            pb.replace_section(this_index, s);
            pb.layout(); // Layout initial pour connaître RVA

            info.name = s.name;
            info.virtualAddress = pb.get_section(this_index).virtualAddress;
            info.virtualSize = pb.get_section(this_index).virtualSize;
            info.sizeOfRawData = pb.get_section(this_index).sizeOfRawData;

            asm_text.prepare(info.virtualAddress);

            // corriger la section
            s.name = ".text";
            s.content = asm_text.content;
            s.virtualAddress = info.virtualAddress;
            s.virtualSize = info.virtualSize;
            s.sizeOfRawData = info.sizeOfRawData;
            s.pointerToRawData = pb.get_section(this_index).pointerToRawData;
            s.characteristics = 0x60000020; // CODE | EXECUTE | READ (emplacement du code à écrire par l'utilisateur)

            pb.replace_section(this_index, s);
            pb.layout(); // re-layout final

            info.section = s;
        }
        else if (type == ".rsrc") {
            rsrc.prepare(0x0);

            if (rsrc.content.size()==0) {
                std::cout << "erreur : rsrc est vide !" << std::endl;
                return;
            }

            s.name = ".rsrc";
            s.content = rsrc.content;
            s.virtualAddress = 0x0;
            s.virtualSize = s.content.size();
            s.sizeOfRawData = s.content.size();
            s.characteristics = 0x40000040; // READ | INITIALIZED_DATA

            if (!as_this_section(type)) {
                pb.push_section(s);
            } else {
                pb.replace_section(this_index, s);
            }
            pb.layout(); // pour obtenir RVA

            info.name = s.name;
            info.virtualAddress = pb.get_section(this_index).virtualAddress;
            info.virtualSize = pb.get_section(this_index).virtualSize;
            info.sizeOfRawData = pb.get_section(this_index).sizeOfRawData;

            rsrc.prepare(pb.get_section(this_index).virtualAddress);

            s.name = ".rsrc";
            s.content = rsrc.content;
            s.virtualAddress = info.virtualAddress;
            s.virtualSize = info.virtualSize;
            s.sizeOfRawData = info.sizeOfRawData;
            s.pointerToRawData = pb.get_section(this_index).pointerToRawData;
            s.characteristics = 0x40000040; // READ | INITIALIZED_DATA

            pb.replace_section(this_index, s);
            pb.layout(); // re-layout final

            // set rsrc directory
            pb.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, info.virtualAddress, s.sizeOfRawData);

            info.section = s;
        }
        else {
            std::cout << "erreur : nom de section inconnu sur push_section(type) : '.text', .data', '.idata' ou '.rsrc' seulement !" << std::endl;
            return;
        }

        if (!as_this_section(type)) {
            //ajouter la nouvelle section à la structure et décaler l'index
            sections.push_back(info);
            section_index++;
        } else {
            // on modifie la section existante
            for (auto& section_ : sections) {
                if (section_.name == type) {
                    section_ = info;   // écrasement complet
                    break;
                }
            }
        }
    }

    void update_section() {
        pb.layout();
        for (auto& section_ : sections) {
            if (section_.name == ".data" || section_.name == ".idata" || section_.name == ".rsrc" || section_.name == ".text") {
                push_section(section_.name);
            }
        }
    }

    // ---- FINAL ----
    void buid_exe() {
        if (!addr_entry_point || name_exe.empty()) {
            std::cout << "erreur addresse d'entrée du code indéfini ou nom du fichier exe null !" << std::endl;
            return; //erreur paramètre nécessaire
        }

        vector<u8> pe = pb.build(size_t(addr_entry_point),is_console);
        // Écrit le fichier
        HANDLE f = CreateFileA(name_exe.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD written;
        WriteFile(f, pe.data(), (DWORD)pe.size(), &written, NULL);
        CloseHandle(f);
    }
};

