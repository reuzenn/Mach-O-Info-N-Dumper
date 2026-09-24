#include <windows.h>
#include <commdlg.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <string>
#include <cstring>
#include <iomanip>
#include <cctype>
#include <sstream>

//methname validation
bool isValidMethodName(const std::string& name) {
    if (name.empty()) return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != ':' && c != '.') {
            return false;
        }
    }
    return true;
}

//MACH-O Structs
struct mach_header_64 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

// --- OBJECTIVE-C STRUCTURES ---
struct objc_class_64 {
    uint64_t isa;
    uint64_t superclass;
    uint64_t cache;
    uint64_t vtable;
    uint64_t data;
};

struct class_ro_64 {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    uint64_t ivarLayout;
    uint64_t name;
    uint64_t baseMethodList;
    uint64_t baseProtocols;
    uint64_t ivars;
    uint64_t weakIvarLayout;
    uint64_t baseProperties;
};

struct method_list_t {
    uint32_t entsizeAndFlags;
    uint32_t count;
};

struct method_t_rel {
    int32_t name_offset;
    int32_t types_offset;
    int32_t imp_offset;
};

//Memory helpers
struct MemSegment{
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
};

std::vector<MemSegment> g_segments;

constexpr uint64_t PAC_MASK = 0x0000000FFFFFFFFF;
constexpr uint64_t FAST_DATA_MASK = 0x00007FFFFFFFFFF8;

uint64_t strip_pac(uint64_t ptr) {
    return ptr & PAC_MASK;
}

uint64_t vmaddr_to_offset(uint64_t target_vmaddr) {
    target_vmaddr = strip_pac(target_vmaddr);
    for (const auto& seg : g_segments) {
        if (target_vmaddr >= seg.vmaddr && target_vmaddr < (seg.vmaddr + seg.vmsize)) {
            return seg.fileoff + (target_vmaddr - seg.vmaddr);
        }
    }
    return 0;
}

std::string read_string(std::ifstream& file, uint64_t offset) {
    if (offset == 0) return "";
    std::string result = "";
    char c;
    std::streampos original = file.tellg();
    file.seekg(offset, std::ios::beg);
    while (file.read(&c, 1) && c != '\0') {
        result += c;
    }
    file.seekg(original, std::ios::beg);
    return result;
}

// Cpu, cpunsubtype and file type helpers
std::string get_cpu_type_name(int32_t cputype) {
    if (cputype == 0x0100000C) return "ARM64";
    if (cputype == 0x01000007) return "X86_64";
    return "UNKNOWN";
}

std::string get_cpu_subtype_name(int32_t cputype, int32_t cpusubtype) {
    if (cputype == 0x0100000C) {
        int32_t base = cpusubtype & 0xFF; // strip ABI/capability bits
        if (base == 0) return "ARM64_ALL";
        if (base == 1) return "ARM64_V8";
        if (base == 2) return "ARM64E (Pointer Authentication)";
        return "ARM64 (unrecognized subtype)";
    }
    if (cputype == 0x01000007) return "X86_64_ALL";
    return "UNKNOWN";
}

std::string get_file_type_name(uint32_t filetype) {
    switch (filetype) {
        case 0x1: return "MH_OBJECT";
        case 0x2: return "MH_EXECUTE";
        case 0x6: return "MH_DYLIB";
        case 0x7: return "MH_DYLINKER";
        case 0x8: return "MH_BUNDLE";
        case 0x9: return "MH_DYLIB_STUB";
        case 0xa: return "MH_DSYM";
        case 0xb: return "MH_KEXT_BUNDLE";
        default:  return "UNKNOWN";
    }
}

std::string get_lc_type(uint32_t cmd) {
    switch (cmd) {
        case 0x1:  return "LC_SEGMENT";
        case 0x2:  return "LC_SYMTAB";
        case 0xb:  return "LC_DYSYMTAB";
        case 0xc:  return "LC_LOAD_DYLIB";
        case 0xd:  return "LC_ID_DYLIB";
        case 0x19: return "LC_SEGMENT_64";
        case 0x1b: return "LC_UUID";
        case 0x1d: return "LC_CODE_SIGNATURE";
        case 0x26: return "LC_FUNCTION_STARTS";
        case 0x2a: return "LC_SOURCE_VERSION";
        case 0x32: return "LC_BUILD_VERSION";
        case 0x80000028: return "LC_MAIN";
        case 0x80000033: return "LC_DYLD_EXPORTS_TRIE";
        case 0x80000034: return "LC_DYLD_CHAINED_FIXUPS";
        default:   return "UNKNOWN_CMD";
    }
}

//Main analysis log
std::string RunAnalysis(const std::string& filepath) {
    std::ostringstream tableOut;
    std::ostringstream infoOut;
    std::ostringstream objcOut;
    std::ostringstream vtableOut;

    // Prevent old data from overlapping across multiple analyses
    g_segments.clear();

    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        return "[-] Error: Could not open file.\n";
    }

    mach_header_64 header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (header.magic != 0xFEEDFACF) {
        return "[-] Error: Not a valid 64-bit Mach-O file.\n";
    }

    //FILE INFORMATION (built now, printed after the table)
    infoOut << "========================================================================\n";
    infoOut << "                           FILE INFORMATION\n";
    infoOut << "========================================================================\n";
    infoOut << "Magic            : 0x" << std::hex << std::setw(8) << std::setfill('0') << header.magic << std::dec << "\n";
    infoOut << "CPU Type         : " << get_cpu_type_name(header.cputype) << "\n";
    infoOut << "CPU Subtype      : " << get_cpu_subtype_name(header.cputype, header.cpusubtype) << "\n";
    infoOut << "Raw CPU Subtype  : 0x" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)header.cpusubtype << std::dec << "\n";
    infoOut << "File Type        : " << get_file_type_name(header.filetype) << " (0x" << std::hex << header.filetype << std::dec << ")\n";
    infoOut << "Command Count    : " << header.ncmds << "\n";
    infoOut << "Commands Size    : " << header.sizeofcmds << " bytes\n";
    infoOut << "Flags            : 0x" << std::hex << std::setw(8) << std::setfill('0') << header.flags << std::dec << "\n";

    // ======================= LOAD COMMANDS / SEGMENTS TABLE (Excel-style) =======================
    char buf[512];
    tableOut << "========================================================================\n";
    tableOut << "                    LOAD COMMANDS / SEGMENTS TABLE\n";
    tableOut << "========================================================================\n";
    snprintf(buf, sizeof(buf), "%-30s | %-20s | %-22s | %s\n", "NAME", "MEMORY ADDRESS", "CMD", "SIZE");
    tableOut << buf;
    tableOut << "------------------------------------------------------------------------------------------------\n";

    uint64_t objc_classlist_offset = 0;
    uint64_t objc_classlist_size = 0;
    uint64_t const_section_offset = 0;
    uint64_t const_section_size = 0;

    for (uint32_t i = 0; i < header.ncmds; i++) {
        std::streampos cmd_start = file.tellg();

        load_command lc;
        file.read(reinterpret_cast<char*>(&lc), sizeof(lc));

        if (lc.cmd == 0x19) { // LC_SEGMENT_64
            segment_command_64 seg;
            file.seekg(cmd_start, std::ios::beg);
            file.read(reinterpret_cast<char*>(&seg), sizeof(seg));

            char segName[17] = {0};
            std::memcpy(segName, seg.segname, 16);

            g_segments.push_back({seg.vmaddr, seg.vmsize, seg.fileoff});

            snprintf(buf, sizeof(buf), "%-30s | 0x%018llx | %-22s | %llu\n",
                     segName, (unsigned long long)seg.vmaddr, "LC_SEGMENT_64", (unsigned long long)seg.vmsize);
            tableOut << buf;

            for (uint32_t j = 0; j < seg.nsects; j++) {
                section_64 sect;
                file.read(reinterpret_cast<char*>(&sect), sizeof(sect));

                char sectName[17] = {0};
                std::memcpy(sectName, sect.sectname, 16);

                std::string indentedName = std::string("  |-- ") + sectName;
                snprintf(buf, sizeof(buf), "%-30s | 0x%018llx | %-22s | %llu\n",
                         indentedName.c_str(), (unsigned long long)sect.addr, "SECTION", (unsigned long long)sect.size);
                tableOut << buf;

                if (std::string(sectName) == "__objc_classlist") {
                    objc_classlist_offset = sect.offset;
                    objc_classlist_size = sect.size;
                }
                else if (std::string(sectName) == "__const") {
                    const_section_offset = sect.offset;
                    const_section_size = sect.size;
                }
            }
        } else {
            snprintf(buf, sizeof(buf), "%-30s | %-20s | %-22s | %u\n",
                     "-", "---", get_lc_type(lc.cmd).c_str(), lc.cmdsize);
            tableOut << buf;
        }

        file.seekg(cmd_start + (std::streamoff)lc.cmdsize, std::ios::beg);
    }

    // obj-c classdump
    objcOut << "========================================================================\n";
    objcOut << "                      OBJECTIVE-C CLASS DUMP\n";
    objcOut << "========================================================================\n";

    if (objc_classlist_offset != 0) {
        uint32_t class_count = objc_classlist_size / 8;
        objcOut << "[+] Found __objc_classlist. Total Classes: " << class_count << "\n\n";

        for (uint32_t i = 0; i < class_count; i++) {
            uint64_t class_ptr = 0;
            file.seekg(objc_classlist_offset + (i * 8), std::ios::beg);
            file.read(reinterpret_cast<char*>(&class_ptr), sizeof(class_ptr));

            uint64_t class_offset = vmaddr_to_offset(class_ptr);
            if (class_offset == 0) continue;

            objc_class_64 objc_cls;
            file.seekg(class_offset, std::ios::beg);
            file.read(reinterpret_cast<char*>(&objc_cls), sizeof(objc_cls));

            uint64_t data_vmaddr = strip_pac(objc_cls.data) & FAST_DATA_MASK;
            uint64_t data_offset = vmaddr_to_offset(data_vmaddr);

            if (data_offset == 0) continue;

            class_ro_64 ro;
            file.seekg(data_offset, std::ios::beg);
            file.read(reinterpret_cast<char*>(&ro), sizeof(ro));

            uint64_t name_offset = vmaddr_to_offset(ro.name);
            std::string className = read_string(file, name_offset);

            if (className.empty() || className.length() < 2) {
                className = "[OBFUSCATED_CLASS]";
            }

            objcOut << "[Class] " << className << " (Addr: 0x" << std::hex << class_ptr << std::dec << ")\n";

            if (ro.baseMethodList != 0) {
                uint64_t methodList_vmaddr = strip_pac(ro.baseMethodList);
                uint64_t methodList_offset = vmaddr_to_offset(methodList_vmaddr);

                if (methodList_offset != 0) {
                    method_list_t mlist;
                    file.seekg(methodList_offset, std::ios::beg);
                    file.read(reinterpret_cast<char*>(&mlist), sizeof(mlist));

                    bool isRelative = (mlist.entsizeAndFlags & 0x80000000) != 0;
                    uint32_t entsize = mlist.entsizeAndFlags & 0xFFFF;

                    for (uint32_t m = 0; m < mlist.count; m++) {
                        if (isRelative) {
                            method_t_rel meth;
                            uint64_t current_method_offset = methodList_offset + sizeof(method_list_t) + (m * entsize);
                            file.seekg(current_method_offset, std::ios::beg);
                            file.read(reinterpret_cast<char*>(&meth), sizeof(meth));

                            uint64_t field_vmaddr = methodList_vmaddr + sizeof(method_list_t) + (m * entsize);
                            uint64_t name_target_vmaddr = field_vmaddr + meth.name_offset;
                            uint64_t name_file_offset = vmaddr_to_offset(name_target_vmaddr);

                            std::string methodName = read_string(file, name_file_offset);

                            if (isValidMethodName(methodName)) {
                                objcOut << "    [-] " << methodName << "\n";
                            }
                        }
                    }
                }
            }
            objcOut << "\n";
        }
    } else {
        objcOut << "[-] __objc_classlist section not found.\n";
    }

    //  C++ VTable heuristics
    vtableOut << "========================================================================\n";
    vtableOut << "                      C++ VTABLE HEURISTICS\n";
    vtableOut << "========================================================================\n";

    if (const_section_offset != 0) {
        uint32_t ptr_count = const_section_size / 8;
        uint32_t vtable_candidates = 0;

        for (uint32_t i = 0; i + 3 <= ptr_count; i += 3) {
            uint64_t p1, p2, p3;
            file.seekg(const_section_offset + (i * 8), std::ios::beg);
            file.read(reinterpret_cast<char*>(&p1), 8);
            file.read(reinterpret_cast<char*>(&p2), 8);
            file.read(reinterpret_cast<char*>(&p3), 8);

            if (vmaddr_to_offset(p1) && vmaddr_to_offset(p2) && vmaddr_to_offset(p3)) {
                vtable_candidates++;
            }
        }
        vtableOut << "[+] Found " << vtable_candidates << " potential C++ VTable blocks in __const.\n";
    } else {
        vtableOut << "[-] __const section not found.\n";
    }

    //final output assembler
    std::ostringstream finalOut;
    finalOut << tableOut.str() << "\n"
             << infoOut.str() << "\n\n"
             << objcOut.str() << "\n"
             << vtableOut.str() << "\nDone.\n";

    return finalOut.str();
}

//WIN32 GUI

HWND hEditPath, hOutputBox, hBtnBrowse, hBtnParse;
HBRUSH hbrBackground = NULL, hbrControl = NULL;

// Charcoal gray color definitions
COLORREF colorBg = RGB(35, 35, 35);       // Background
COLORREF colorCtrl = RGB(25, 25, 25);     // Text box interior
COLORREF colorText = RGB(220, 220, 220);  // Text (light gray)

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            hbrBackground = CreateSolidBrush(colorBg);
            hbrControl = CreateSolidBrush(colorCtrl);

            // Classic console-style font
            HFONT hFont = CreateFontA(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                      ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

            hEditPath = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
                15, 15, 520, 25, hwnd, NULL, NULL, NULL);

            hBtnBrowse = CreateWindowA("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE | BS_FLAT,
                545, 14, 100, 27, hwnd, (HMENU)1, NULL, NULL);

            hBtnParse = CreateWindowA("BUTTON", "Analyze", WS_CHILD | WS_VISIBLE | BS_FLAT,
                655, 14, 100, 27, hwnd, (HMENU)2, NULL, NULL);

            hOutputBox = CreateWindowA("EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                15, 55, 740, 480, hwnd, NULL, NULL, NULL);

            SendMessage(hEditPath, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hBtnBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hBtnParse, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hOutputBox, WM_SETFONT, (WPARAM)hFont, TRUE);
            return 0;
        }

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, colorText);
            SetBkColor(hdc, colorCtrl);
            return (LRESULT)hbrControl;
        }

        case WM_CTLCOLORBTN: {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, colorText);
            SetBkColor(hdc, colorBg);
            return (LRESULT)hbrBackground;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == 1) { // Browse
                OPENFILENAMEA ofn;
                char szFile[260] = { 0 };
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = "All Files\0*.*\0Mach-O\0*.dylib\0";
                ofn.nFilterIndex = 1;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

                if (GetOpenFileNameA(&ofn)) {
                    SetWindowTextA(hEditPath, ofn.lpstrFile);
                }
            }
            if (LOWORD(wParam) == 2) { // Analyze
                char path[260];
                GetWindowTextA(hEditPath, path, 260);
                if (strlen(path) > 0) {
                    SetWindowTextA(hOutputBox, "Analyzing, please wait...");
                    UpdateWindow(hOutputBox);

                    std::string result = RunAnalysis(path);

                    // Windows edit controls require line endings converted to \r\n
                    std::string winResult = "";
                    for (char c : result) {
                        if (c == '\n') winResult += "\r\n";
                        else winResult += c;
                    }

                    SetWindowTextA(hOutputBox, winResult.c_str());
                } else {
                    SetWindowTextA(hOutputBox, "Please select a file first.");
                }
            }
            return 0;
        }

        case WM_ERASEBKGND: {
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, hbrBackground);
            return 1;
        }

        case WM_DESTROY: {
            DeleteObject(hbrBackground);
            DeleteObject(hbrControl);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "DarkMachOExplorer";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClassA(&wc)) return 0;

    HWND hwnd = CreateWindowA(
        wc.lpszClassName,
        "Mach-O Explorer - Lightweight Edition",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 785, 590,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}