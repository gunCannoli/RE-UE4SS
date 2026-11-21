#pragma once
// WMM Pak Enabler — version-agnostic UE5 unsigned ~mods pak enabler.
//
// Pure Win32 / C++17, zero heap/CRT/STL locks (100% DllMain loader-lock safe).
// Shared header-only module usable from both:
//   1. Standalone dsound.dll proxy (for paks-only users without UE4SS)
//   2. gunCannoli/RE-UE4SS dwmapi.dll proxy (zero extra proxy DLLs)
//
// Strategy 1 (Primary, zero-padding, version-agnostic):
//   Locates UnrealBuildTool's auto-generated RSA-2048 public-key callback
//   (stack init of RSA exponent 0x010001 = 65537) and finds the unique
//   static-initializer thunk `lea rcx, [cb]; jmp BindStatic`. Patches
//   BindStatic with a single 0xC3 (RET) in memory (never modifies disk exe).
//
// Strategy 2 (Fallback):
//   Optional external pattern rules in `wmm_pak_enabler.ini` next to the exe,
//   allowing WMM to ship rule updates without recompiling the DLL.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

namespace wmm {

struct EnablerResult {
    bool ok = false;
    const char* strategy = "none";
    uintptr_t target_addr = 0;
    uint32_t target_rva = 0;
    double elapsed_ms = 0.0;
    const char* detail = "";
};

namespace detail {

inline bool get_text_section(HMODULE mod, const uint8_t*& base_out, uint32_t& rva_out, size_t& size_out) {
    auto* base = reinterpret_cast<const uint8_t*>(mod);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::memcmp(sec->Name, ".text", 5) == 0) {
            base_out = base;
            rva_out = sec->VirtualAddress;
            size_out = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            return true;
        }
    }
    return false;
}

inline int32_t read_i32(const uint8_t* p) {
    int32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

// Strategy 1: RSA-2048 exponent (0x010001) callback -> `lea rcx, [cb]; jmp BindStatic`
inline bool resolve_rsa_thunk(const uint8_t* img_base, uint32_t text_rva, size_t text_size, uint32_t& out_target_rva) {
    const uint8_t* text = img_base + text_rva;
    uint32_t candidates[32];
    int cand_count = 0;

    // Match: 66 C7 44 24 <off> 01 00 ... (within 16 bytes) ... C6 44 24 <off+2> 01
    for (size_t i = 0; i + 28 < text_size; ++i) {
        if (text[i] == 0x66 && text[i + 1] == 0xC7 && text[i + 2] == 0x44 &&
            text[i + 3] == 0x24 && text[i + 5] == 0x01 && text[i + 6] == 0x00) {
            uint8_t exp_off = text[i + 4];
            bool found_hi = false;
            for (size_t j = i + 7; j <= i + 23 && j + 5 < text_size; ++j) {
                if (text[j] == 0xC6 && text[j + 1] == 0x44 && text[j + 2] == 0x24 &&
                    text[j + 3] == static_cast<uint8_t>(exp_off + 2) && text[j + 4] == 0x01) {
                    found_hi = true;
                    break;
                }
            }
            if (!found_hi) continue;

            // Backtrack up to 160 bytes to find 16-byte aligned function start after 0xCC padding
            size_t start = i;
            size_t limit = (i > 160) ? (i - 160) : 0;
            while (start > limit) {
                if (text[start - 1] == 0xCC && ((text_rva + start) & 0xF) == 0) {
                    break;
                }
                --start;
            }
            uint32_t cb_rva = text_rva + static_cast<uint32_t>(start);
            if (cand_count < 32 && (cand_count == 0 || candidates[cand_count - 1] != cb_rva)) {
                candidates[cand_count++] = cb_rva;
            }
        }
    }

    if (cand_count == 0) return false;

    // Scan .text for static-initializer thunk: 48 8D 0D <rel32> E9 <rel32>
    uint32_t resolved = 0;
    int match_count = 0;
    for (size_t i = 0; i + 12 <= text_size; ++i) {
        if (text[i] == 0x48 && text[i + 1] == 0x8D && text[i + 2] == 0x0D && text[i + 7] == 0xE9) {
            uint32_t rva = text_rva + static_cast<uint32_t>(i);
            int32_t lea_disp = read_i32(text + i + 3);
            uint32_t lea_tgt = static_cast<uint32_t>(static_cast<int64_t>(rva) + 7 + lea_disp);
            for (int c = 0; c < cand_count; ++c) {
                if (lea_tgt == candidates[c]) {
                    int32_t jmp_disp = read_i32(text + i + 8);
                    resolved = static_cast<uint32_t>(static_cast<int64_t>(rva) + 12 + jmp_disp);
                    ++match_count;
                    break;
                }
            }
        }
    }

    if (match_count == 1 && resolved >= text_rva && resolved < text_rva + text_size) {
        out_target_rva = resolved;
        return true;
    }
    return false;
}

// Strategy 2: Optional external pattern rule file (`wmm_pak_enabler.ini`)
inline bool resolve_ini_fallback(
    const wchar_t* exe_dir,
    const uint8_t* img_base,
    uint32_t text_rva,
    size_t text_size,
    uint32_t& out_target_rva) {
    wchar_t ini_path[MAX_PATH + 32];
    std::swprintf(ini_path, MAX_PATH + 32, L"%ls\\wmm_pak_enabler.ini", exe_dir);

    HANDLE hf = CreateFileW(ini_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;

    char buf[4096];
    DWORD nread = 0;
    BOOL ok = ReadFile(hf, buf, sizeof(buf) - 1, &nread, nullptr);
    CloseHandle(hf);
    if (!ok || nread == 0) return false;
    buf[nread] = '\0';

    int pat[256];
    int pat_len = 0;
    int jmp_offset = -1;

    char* line = buf;
    while (line && *line) {
        char* nl = std::strchr(line, '\n');
        if (nl) *nl = '\0';
        size_t len = std::strlen(line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == ' ')) line[--len] = '\0';

        if (std::strncmp(line, "pattern=", 8) == 0) {
            const char* p = line + 8;
            while (*p && pat_len < 256) {
                while (*p == ' ' || *p == '\t') ++p;
                if (!*p) break;
                if (*p == '?') {
                    pat[pat_len++] = -1;
                    while (*p && *p != ' ' && *p != '\t') ++p;
                } else {
                    char* endp = nullptr;
                    pat[pat_len++] = static_cast<int>(std::strtol(p, &endp, 16)) & 0xFF;
                    p = (endp && endp > p) ? endp : (p + 1);
                }
            }
        } else if (std::strncmp(line, "jmp_offset=", 11) == 0) {
            jmp_offset = static_cast<int>(std::strtol(line + 11, nullptr, 0));
        }
        line = nl ? (nl + 1) : nullptr;
    }

    if (pat_len <= 0 || static_cast<size_t>(pat_len) >= text_size) return false;

    const uint8_t* text = img_base + text_rva;
    for (size_t i = 0; i + static_cast<size_t>(pat_len) <= text_size; ++i) {
        bool match = true;
        for (int j = 0; j < pat_len; ++j) {
            if (pat[j] != -1 && text[i + j] != static_cast<uint8_t>(pat[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            uint32_t match_rva = text_rva + static_cast<uint32_t>(i);
            if (jmp_offset >= 0 && i + static_cast<size_t>(jmp_offset) + 5 <= text_size) {
                const uint8_t* jp = text + i + jmp_offset;
                if (*jp == 0xE9) {
                    int32_t disp = read_i32(jp + 1);
                    out_target_rva = static_cast<uint32_t>(static_cast<int64_t>(match_rva + jmp_offset) + 5 + disp);
                    return true;
                }
            } else {
                out_target_rva = match_rva;
                return true;
            }
        }
    }
    return false;
}

inline bool write_ret_byte(uintptr_t addr) {
    DWORD old_prot = 0;
    auto* p = reinterpret_cast<uint8_t*>(addr);
    if (*p == 0xC3) return true;
    if (!VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old_prot)) return false;
    *p = 0xC3;
    FlushInstructionCache(GetCurrentProcess(), p, 1);
    DWORD dummy = 0;
    VirtualProtect(p, 1, old_prot, &dummy);
    return true;
}

inline void get_exe_dir(wchar_t* out, DWORD cap) {
    DWORD n = GetModuleFileNameW(nullptr, out, cap);
    while (n > 0 && out[n - 1] != L'\\' && out[n - 1] != L'/') --n;
    if (n > 0) out[n - 1] = L'\0';
    else out[0] = L'.', out[1] = L'\0';
}

inline void write_log(const wchar_t* exe_dir, const EnablerResult& res) {
    wchar_t log_path[MAX_PATH + 32];
    std::swprintf(log_path, MAX_PATH + 32, L"%ls\\wmm_pak_enabler.log", exe_dir);
    HANDLE hf = CreateFileW(log_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    char msg[512];
    int len = std::snprintf(
        msg,
        sizeof(msg),
        "[WMM_PakEnabler] status=%s strategy=%s rva=0x%08X addr=0x%llX elapsed=%.2fms detail=%s\n",
        res.ok ? "OK" : "FAIL",
        res.strategy,
        res.target_rva,
        static_cast<unsigned long long>(res.target_addr),
        res.elapsed_ms,
        res.detail);
    if (len > 0) {
        DWORD written = 0;
        WriteFile(hf, msg, static_cast<DWORD>(len), &written, nullptr);
    }
    CloseHandle(hf);
}

}  // namespace detail

inline EnablerResult enable_unsigned_paks() {
    EnablerResult res;
    LARGE_INTEGER freq{}, t0{}, t1{};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    wchar_t exe_dir[MAX_PATH] = {};
    detail::get_exe_dir(exe_dir, MAX_PATH);
    HMODULE exe_mod = GetModuleHandleW(nullptr);
    const uint8_t* img_base = nullptr;
    uint32_t text_rva = 0;
    size_t text_size = 0;

    if (!detail::get_text_section(exe_mod, img_base, text_rva, text_size)) {
        res.detail = "PE .text section not found";
    } else {
        uint32_t target_rva = 0;
        if (detail::resolve_rsa_thunk(img_base, text_rva, text_size, target_rva)) {
            res.strategy = "rsa_thunk";
            res.target_rva = target_rva;
            res.target_addr = reinterpret_cast<uintptr_t>(img_base + target_rva);
            res.ok = detail::write_ret_byte(res.target_addr);
            res.detail = res.ok ? "patched BindStatic with RET" : "VirtualProtect failed";
        } else if (detail::resolve_ini_fallback(exe_dir, img_base, text_rva, text_size, target_rva)) {
            res.strategy = "ini_fallback";
            res.target_rva = target_rva;
            res.target_addr = reinterpret_cast<uintptr_t>(img_base + target_rva);
            res.ok = detail::write_ret_byte(res.target_addr);
            res.detail = res.ok ? "patched via ini fallback" : "VirtualProtect failed";
        } else {
            res.detail = "no matching pak-signing registration target found";
        }
    }

    QueryPerformanceCounter(&t1);
    if (freq.QuadPart > 0) {
        res.elapsed_ms = static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000.0 / static_cast<double>(freq.QuadPart);
    }
    detail::write_log(exe_dir, res);
    return res;
}

}  // namespace wmm
