#include <FaultLog.hpp>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>

#include <Unreal/Core/Windows/WindowsHWrapper.hpp>
#include <Unreal/UObject.hpp>
#include <Unreal/UClass.hpp>
#include <LuaMadeSimple/LuaMadeSimple.hpp>

namespace RC::FaultLog
{
    namespace
    {
        constexpr size_t ring_size = 32;
        constexpr int max_entries_written = 120;

        struct Entry
        {
            Kind kind{};
            const void* object{};
            const void* aux{};
            char name[40]{};
            uint64_t counter{};
        };

        Entry g_ring[ring_size]{};
        std::atomic<uint64_t> g_head{0};
        std::atomic<uint64_t> g_faults{0};
        std::atomic<uint64_t> g_caught{0};
        std::atomic<uint64_t> g_stale{0};
        std::atomic<int> g_written{0};
        HANDLE g_file = INVALID_HANDLE_VALUE;
        PVOID g_veh = nullptr;
        thread_local int t_guard_depth = 0;
        thread_local bool t_in_handler = false;

        auto write_raw(const char* text, size_t len) -> void
        {
            if (g_file == INVALID_HANDLE_VALUE || len == 0) return;
            DWORD written{};
            WriteFile(g_file, text, static_cast<DWORD>(len), &written, nullptr);
        }

        // Fixed-buffer appender: no heap, so it is safe inside a fault.
        struct Buf
        {
            char data[6144];
            size_t len{};
            auto add(const char* fmt, ...) -> void
            {
                if (len >= sizeof(data) - 1) return;
                va_list args;
                va_start(args, fmt);
                const int n = vsnprintf(data + len, sizeof(data) - len, fmt, args);
                va_end(args);
                if (n > 0) len = (len + static_cast<size_t>(n) < sizeof(data)) ? len + static_cast<size_t>(n) : sizeof(data) - 1;
            }
        };
        Buf g_buf{};

        auto module_of(const void* address, char* out, size_t out_size, uint64_t* offset) -> void
        {
            out[0] = 0;
            *offset = reinterpret_cast<uint64_t>(address);
            HMODULE module{};
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCSTR>(address), &module) && module)
            {
                char path[MAX_PATH]{};
                GetModuleFileNameA(module, path, MAX_PATH);
                const char* base = strrchr(path, '\\');
                strncpy_s(out, out_size, base ? base + 1 : path, _TRUNCATE);
                *offset = reinterpret_cast<uint64_t>(address) - reinterpret_cast<uint64_t>(module);
            }
        }

        // The Lua call stack of the state that last entered a C function (the mod that was running).
        auto lua_stack_of(Buf& buf, lua_State* L) -> void
        {
            if (!L)
            {
                buf.add("  lua: no active Lua call\n");
                return;
            }
            lua_Debug ar{};
            for (int level = 0; level < 14; ++level)
            {
                if (!lua_getstack(L, level, &ar)) break;
                if (!lua_getinfo(L, "Sln", &ar)) break;
                buf.add("  lua[%d]: %s:%d in %s %s\n", level, ar.short_src, ar.currentline, ar.namewhat ? ar.namewhat : "", ar.name ? ar.name : "?");
            }
        }

        auto lua_stack(Buf& buf) -> void
        {
            lua_stack_of(buf, LuaMadeSimple::active_lua_state());
        }

        // Name of an object (class name or own name), copied as plain ASCII; "<unreadable>" when the object is freed. The unsafe part runs under guard().
        struct NameCtx
        {
            const void* object;
            bool class_name;
            char* out;
            size_t out_size;
        };

        auto name_thunk(void* raw) -> void
        {
            auto* c = static_cast<NameCtx*>(raw);
            const auto* obj = static_cast<const Unreal::UObject*>(c->object);
            const Unreal::UObject* target = c->class_name ? static_cast<const Unreal::UObject*>(obj->GetClassPrivate()) : obj;
            if (!target) return;
            const auto name = target->GetNamePrivate().ToString();
            size_t i = 0;
            for (; i + 1 < c->out_size && i < name.size(); ++i) c->out[i] = static_cast<char>(name[i] & 0x7f);
            c->out[i] = 0;
        }

        auto resolve_name(const void* object, bool class_name, char* out, size_t out_size) -> void
        {
            out[0] = 0;
            if (!object) return;
            NameCtx ctx{object, class_name, out, out_size};
            unsigned long code{};
            if (!guard(name_thunk, &ctx, &code)) strncpy_s(out, out_size, "<unreadable>", _TRUNCATE);
        }

        auto is_fault_code(DWORD code) -> bool
        {
            return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR || code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_STACK_OVERFLOW ||
                   code == EXCEPTION_PRIV_INSTRUCTION || code == EXCEPTION_INT_DIVIDE_BY_ZERO;
        }

        auto describe_fault(PEXCEPTION_POINTERS info) -> void
        {
            Buf& buf = g_buf;
            buf.len = 0;
            const DWORD code = info->ExceptionRecord->ExceptionCode;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char mod[64]{};
            uint64_t off{};
            module_of(info->ExceptionRecord->ExceptionAddress, mod, sizeof(mod), &off);
            const bool guarded = t_guard_depth > 0;
            const bool resolve_names = guarded || _stricmp(mod, "UE4SS.dll") == 0;
            buf.add("[FAULT%s] %04d-%02d-%02d %02d:%02d:%02d.%03d thread=%lu code=0x%08lX at %s+0x%llx", guarded ? "-GUARDED" : "", st.wYear, st.wMonth, st.wDay, st.wHour,
                    st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId(), code, mod, static_cast<unsigned long long>(off));
            if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) && info->ExceptionRecord->NumberParameters >= 2)
            {
                const ULONG_PTR kind = info->ExceptionRecord->ExceptionInformation[0];
                buf.add(" %s address 0x%llx", kind == 0 ? "reading" : (kind == 1 ? "writing" : "executing"),
                        static_cast<unsigned long long>(info->ExceptionRecord->ExceptionInformation[1]));
            }
            buf.add("%s\n", guarded ? "  (inside a guarded Lua property access: converted to a Lua error)" : "");
            lua_stack(buf);
            const uint64_t head = g_head.load(std::memory_order_relaxed);
            const size_t count = head < ring_size ? static_cast<size_t>(head) : ring_size;
            const size_t shown = count < 16 ? count : 16;
            buf.add("  last %zu Lua->engine operations, newest first:\n", shown);
            for (size_t i = 0; i < shown; ++i)
            {
                const Entry& e = g_ring[(head - 1 - i) % ring_size];
                char cls[48]{};
                char fn[48]{};
                // Names are resolved (heap allocation) only for faults in UE4SS.dll or inside a guard: a fault in the heap itself must not deadlock the handler.
                if (resolve_names)
                {
                    if (e.kind == Kind::Call) resolve_name(e.aux, false, fn, sizeof(fn));
                    resolve_name(e.object, true, cls, sizeof(cls));
                }
                buf.add("    #%llu %s object=%p class=%s %s%s\n", static_cast<unsigned long long>(e.counter),
                        e.kind == Kind::PropGet ? "get " : (e.kind == Kind::PropSet ? "SET " : "CALL"), e.object, cls[0] ? cls : "?",
                        e.kind == Kind::Call ? "function=" : "property=", e.kind == Kind::Call ? fn : e.name);
            }
            write_raw(buf.data, buf.len);
        }

        // Lua panic (an error with no protected call, then abort()): same file, same recent-operations list, the message of the Lua error and the Lua stack of the erroring thread.
        auto panic_logger(lua_State* L, const char* message) -> void
        {
            Buf& buf = g_buf;
            buf.len = 0;
            SYSTEMTIME st{};
            GetLocalTime(&st);
            buf.add("[LUA-PANIC] %04d-%02d-%02d %02d:%02d:%02d.%03d thread=%lu: %s  (Lua is about to abort(): an error was raised with no pcall on the stack, often a mod whose main script failed but kept loops or hooks)\n", st.wYear,
                    st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId(), message);
            lua_stack_of(buf, L);
            const uint64_t head = g_head.load(std::memory_order_relaxed);
            const size_t count = head < ring_size ? static_cast<size_t>(head) : ring_size;
            const size_t shown = count < 8 ? count : 8;
            buf.add("  last %zu Lua->engine operations, newest first:\n", shown);
            for (size_t i = 0; i < shown; ++i)
            {
                const Entry& e = g_ring[(head - 1 - i) % ring_size];
                buf.add("    #%llu %s object=%p %s%s\n", static_cast<unsigned long long>(e.counter), e.kind == Kind::PropGet ? "get " : (e.kind == Kind::PropSet ? "SET " : "CALL"), e.object,
                        e.kind == Kind::Call ? "function@" : "property=", e.kind == Kind::Call ? "(call)" : e.name);
            }
            write_raw(buf.data, buf.len);
        }

        LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS info)
        {
            const DWORD code = info->ExceptionRecord->ExceptionCode;
            if (!is_fault_code(code) || t_in_handler) return EXCEPTION_CONTINUE_SEARCH;
            t_in_handler = true;
            g_faults.fetch_add(1, std::memory_order_relaxed);
            if (g_written.fetch_add(1, std::memory_order_relaxed) < max_entries_written) describe_fault(info);
            t_in_handler = false;
            return EXCEPTION_CONTINUE_SEARCH;
        }

        auto object_probe(void* ctx) -> void
        {
            auto* p = static_cast<std::pair<const void*, bool>*>(ctx);
            const auto* obj = static_cast<const Unreal::UObject*>(p->first);
            auto* cls = obj->GetClassPrivate();
            p->second = cls && cls->GetClassPrivate() != nullptr;
        }
    } // namespace

    auto install(const wchar_t* working_dir) -> void
    {
        if (g_veh) return;
        const std::wstring path = std::wstring{working_dir} + L"\\ue4ss_fault.log";
        const std::wstring prev = std::wstring{working_dir} + L"\\ue4ss_fault.prev.log";
        MoveFileExW(path.c_str(), prev.c_str(), MOVEFILE_REPLACE_EXISTING);
        g_file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        g_veh = AddVectoredExceptionHandler(1, vectored_handler);
        LuaMadeSimple::set_panic_logger(&panic_logger);
    }

    auto note(Kind kind, const void* object, const void* aux, const wchar_t* name16, const char* name8) -> void
    {
        const uint64_t slot = g_head.fetch_add(1, std::memory_order_relaxed);
        Entry& e = g_ring[slot % ring_size];
        e.kind = kind;
        e.object = object;
        e.aux = aux;
        e.counter = slot;
        size_t i = 0;
        if (name16)
        {
            for (; i + 1 < sizeof(e.name) && name16[i]; ++i) e.name[i] = static_cast<char>(name16[i] & 0x7f);
        }
        else if (name8)
        {
            for (; i + 1 < sizeof(e.name) && name8[i]; ++i) e.name[i] = name8[i];
        }
        e.name[i] = 0;
    }

    namespace
    {
        // No C++ objects with destructors may live in a function that uses __try, so the depth counter is kept by a wrapper.
        auto guard_inner(void (*fn)(void*), void* ctx, unsigned long* code) -> bool
        {
            __try
            {
                fn(ctx);
                return true;
            }
            __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
            {
                *code = GetExceptionCode();
                return false;
            }
        }

        struct DepthScope
        {
            DepthScope() { ++t_guard_depth; }
            ~DepthScope() { --t_guard_depth; }
        };
    } // namespace

    auto guard(void (*fn)(void*), void* ctx, unsigned long* code) -> bool
    {
        DepthScope scope{};
        return guard_inner(fn, ctx, code);
    }

    auto object_readable(const void* object) -> bool
    {
        if (!object) return false;
        std::pair<const void*, bool> probe{object, false};
        unsigned long code{};
        if (!guard(object_probe, &probe, &code)) return false;
        return probe.second;
    }

    auto count_stale_blocked() -> void
    {
        g_stale.fetch_add(1, std::memory_order_relaxed);
    }
    auto count_caught() -> void
    {
        g_caught.fetch_add(1, std::memory_order_relaxed);
    }
    auto stats() -> Stats
    {
        return {g_faults.load(), g_caught.load(), g_stale.load()};
    }
} // namespace RC::FaultLog
