#pragma once

// FaultLog (fork addition, 2026-11-09): makes native crashes and stale-UObject accesses from Lua diagnosable.
//  - install(): a vectored exception handler logs every access violation / illegal instruction / stack overflow BEFORE the game's crash reporter
//    takes the process: fault address as module+offset, the Lua call stack of the running mod (file:line), and the last operations Lua asked the engine
//    to do (property get / set, function call, with the object and the name). It writes <working dir>\ue4ss_fault.log directly with WriteFile (no
//    allocation, no locks); the next launch moves that file to ue4ss_fault.prev.log and echoes it into UE4SS.log as [FAULT-PREV] lines.
//  - guard(): runs a function under SEH and turns an access violation into a return value, so a Lua property access on a freed UObject becomes a
//    catchable Lua error instead of a process crash.
//  - object_readable(): a cheap probe (class pointer of the object and of its class) under SEH.

#include <cstdint>

struct lua_State;

namespace RC::FaultLog
{
    enum class Kind : uint8_t
    {
        PropGet,
        PropSet,
        Call,
    };

    struct Stats
    {
        uint64_t faults;        // fault exceptions seen by the handler (first chance, includes guarded ones)
        uint64_t caught;        // faults converted into Lua errors by guard()
        uint64_t stale_blocked; // accesses refused by the stale-object probe before they could fault
    };

    // Installs the handler once; working_dir is where ue4ss_fault.log is written.
    auto install(const wchar_t* working_dir) -> void;

    // Remembers the latest operation (ring of 32). Exactly one of name16 / name8 may be set. Cheap enough for the property hot path.
    auto note(Kind kind, const void* object, const void* aux, const wchar_t* name16, const char* name8) -> void;

    // Runs fn(ctx) under SEH. Returns false when it raised an access violation / in-page error (code is stored); other exceptions pass through.
    auto guard(void (*fn)(void*), void* ctx, unsigned long* code) -> bool;

    // true when the object's class pointer chain can be read (a freed or reused object usually fails this).
    auto object_readable(const void* object) -> bool;

    auto count_stale_blocked() -> void;
    auto count_caught() -> void;
    auto stats() -> Stats;
} // namespace RC::FaultLog
