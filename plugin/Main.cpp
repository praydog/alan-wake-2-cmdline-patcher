#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <utility/Module.hpp>
#include <utility/Patch.hpp>
#include <utility/RTTI.hpp>

#include <stacktrace>

bool ret1() {
    return true;
}

bool g_already_patched = false;

void startup_thread() {
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

    // Set up spdlog to sink to the console
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] [cmdline-plugin] %v");
    spdlog::set_level(spdlog::level::info);
    spdlog::flush_on(spdlog::level::info);
    spdlog::set_default_logger(spdlog::stdout_logger_mt("console"));

    SPDLOG_INFO("Initializing...");

    const auto vtable = utility::rtti::find_vtable(utility::get_executable(), "class std::_Func_impl_no_alloc<bool (__cdecl*)(void),bool>");

    if (!vtable) {
        SPDLOG_ERROR("Failed to find vtable");
        return;
    }

    SPDLOG_INFO("Found vtable at 0x{:X}", *vtable);

    auto vtp = (uintptr_t*)*vtable;

    Patch::protect((uintptr_t)&vtp[2], sizeof(void*), PAGE_EXECUTE_READWRITE);
    vtp[2] = (uintptr_t)ret1;

    SPDLOG_INFO("Patched vtable[2] to 0x{:X}", vtp[2]);
}

bool IsUALPresent() {
    for (const auto& entry : std::stacktrace::current()) {
        HMODULE hModule = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)entry.native_handle(), &hModule)) {
            if (GetProcAddress(hModule, "IsUltimateASILoader") != NULL)
                return true;
        }
    }
    return false;
}

extern "C" __declspec(dllexport) void InitializeASI()
{
    if (g_already_patched) {
        return;
    }

    g_already_patched = true;
    startup_thread();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        if (!IsUALPresent()) { InitializeASI(); }
    }

    return TRUE;
}