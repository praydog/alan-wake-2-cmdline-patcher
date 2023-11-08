#include <filesystem>
#include <fstream>

#include <windows.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/Patch.hpp>
#include <utility/Thread.hpp>
#include <utility/ScopeGuard.hpp>
#include <utility/RTTI.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

class PEModule {
public:
    PEModule(HMODULE existing_module)
        : m_module{(uintptr_t)existing_module}
    {
        setup();
    }

    PEModule(std::string_view path) {
        memory_map(path);
        setup();
    }

    virtual ~PEModule() {
        if (valid()) {
            const auto now = std::chrono::steady_clock::now();
            // big brain time
            while (FreeLibrary((HMODULE)m_module)) {
                const auto now2 = std::chrono::steady_clock::now();
                const auto elapsed = now2 - now;

                if (elapsed >= std::chrono::seconds(1)) {
                    SPDLOG_ERROR("Failed to unload module after 1 second, aborting");
                    break;
                }

                std::this_thread::yield();
            }
        }
    }

    void setup() {
        if (!valid()) {
            return;
        }

        m_module_path = *utility::get_module_path((HMODULE)m_module);
    }

    void memory_map(std::string_view path) {
        SPDLOG_INFO("Attempting to memory map PE file \"{}\"...", path.data());

        if (path.data() == nullptr || path.empty()) {
            SPDLOG_ERROR("Invalid path");
            return;
        }

        if (!std::filesystem::exists(path)) {
            SPDLOG_ERROR("File \"{}\" does not exist", path.data());
            return;
        }

        const auto short_path = std::filesystem::path(path).filename().string();
        
        m_module = (uintptr_t)LoadLibraryExA(path.data(), nullptr, DONT_RESOLVE_DLL_REFERENCES);

        if (m_module == 0) {
            SPDLOG_ERROR("Failed to memory map PE file \"{}\"", short_path.data());
            return;
        }

        m_file_data = utility::read_module_from_disk((HMODULE)m_module);
        m_module_size = *utility::get_module_size((HMODULE)m_module);

        SPDLOG_ERROR("Successfully memory mapped PE file \"{}\"", short_path.data());
    }

    auto get_base() const {
        return m_module;
    }

    auto get_size() const {
        return m_module_size;
    }

    const auto& get_path() const {
        return m_module_path;
    }

    bool valid() const {
        return m_module != 0;
    }

    operator HMODULE() const {
        return (HMODULE)m_module;
    }

    auto& get_file_data() {
        return m_file_data;
    }

private:
    uintptr_t m_module{};
    size_t m_module_size{};
    std::string m_module_path{};
    std::vector<uint8_t> m_file_data{};
};

std::vector<uint8_t> get_patched_bytes(std::filesystem::path path) {
    // Create a PEModule from the path
    PEModule module{path.string()};
    if (!module.valid()) {
        SPDLOG_ERROR("Failed to create PEModule from \"{}\"", path.string());
        return {};
    }

    // This vtable's third function (vtable[2]) is what is responsible for
    // determining whether certain command line arguments are allowed to be parsed
    // in Alan Wake 2. We will patch this function to always return true.
    // by making it point to a function that just returns true.
    const auto vtable = utility::rtti::find_vtable(module, "class std::_Func_impl_no_alloc<bool (__cdecl*)(void),bool>");

    if (!vtable) {
        SPDLOG_ERROR("Failed to find vtable, cannot patch");
        return {};
    }

    SPDLOG_INFO("Found vtable at 0x{:X}", *vtable - module.get_base());
    const auto rva = *vtable - module.get_base();

    // temporarily map the DLL's file version into memory
    const auto dll = module.get_file_data();
    const auto disk_ptr = utility::ptr_from_rva((uint8_t*)dll.data(), rva);
    if (disk_ptr) {
        const auto disk_offset = *disk_ptr - (uintptr_t)dll.data();
        SPDLOG_INFO("Found vtable at 0x{:X} (disk offset)", disk_offset);

        // Print out pointers to the first 10 functions in the vtable
        // get the module imagebase first (the one in the PE header)
        const auto imagebase = utility::get_dll_imagebase((uintptr_t)dll.data()).value_or(0);
        const auto vt_ptr = (uintptr_t*)*disk_ptr;

        // Just log stuff in the vtable for verification later if something fails
        for (auto i = 0; i < 10; ++i) {
            const auto func_disk = vt_ptr[i];
            const auto func_memory = module.get_base() + (func_disk - imagebase);

            SPDLOG_INFO("vtable[{}] = 0x{:X} (disk offset)", i, func_disk);

            // Print first instruction of each function
            const auto decoded = utility::decode_one((uint8_t*)func_memory);

            if (decoded) {
                char text[ND_MIN_BUF_SIZE]{};
                NdToText(&*decoded, 0, sizeof(text), text);

                SPDLOG_INFO(" {}", text);
            }
        }

        // Sigscan for a mov al, 01; ret set of instructions. we will
        // make vtable[2] point towards this.

        const auto return_true_fn = utility::scan(module, "B0 01 C3");

        if (!return_true_fn) {
            SPDLOG_ERROR("Failed to find return_true_fn, cannot patch");
            return {};
        }

        const auto return_true_rva = *return_true_fn - module.get_base();
        SPDLOG_INFO("Found return_true_fn at 0x{:X} (RVA)", return_true_rva);

        const auto return_true_disk = utility::ptr_from_rva((uint8_t*)dll.data(), return_true_rva);

        if (!return_true_disk) {
            SPDLOG_ERROR("Failed to find return_true_fn (disk), cannot patch");
            return {};
        }
        
        SPDLOG_INFO("Found return_true_fn at 0x{:X} (disk offset)", *return_true_disk - (uintptr_t)dll.data());

        // This one is what we will directly write to the disk offset of &vtable[2]
        const auto return_true_preferred_imagebase = imagebase + return_true_rva;
        SPDLOG_INFO("return_true_fn (preferred imagebase) = 0x{:X}", return_true_preferred_imagebase);

        auto& vt_func_2 = vt_ptr[2];
        const auto vt_func_2_disk_offset = (uintptr_t)&vt_func_2 - (uintptr_t)dll.data();

        SPDLOG_INFO("vtable[2] (disk address) = 0x{:X}", vt_func_2_disk_offset);
        SPDLOG_INFO("vtable[2] (disk value) = 0x{:X}", vt_func_2);

        if (vt_func_2 == return_true_preferred_imagebase) {
            SPDLOG_INFO("vtable[2] is already patched, aborting");
            return {};
        }

        // Create a backup of the file
        const auto backup_path = path.string() + ".bak_" + std::to_string(GetTickCount());
        SPDLOG_INFO("Creating backup of \"{}\" at \"{}\"", path.string(), backup_path);
        {
            std::ofstream backup{backup_path, std::ios::binary};

            if (!backup) {
                SPDLOG_ERROR("Failed to create backup of \"{}\"", path.string());
                SPDLOG_ERROR("Aborting patching process");
                return {};
            }

            backup.write((char*)dll.data(), dll.size());
        }

        // Write the new value, and then write the patched file to disk
        SPDLOG_INFO("Writing 0x{:X} to 0x{:X} (disk)", return_true_preferred_imagebase, vt_func_2_disk_offset);
        vt_func_2 = return_true_preferred_imagebase;

        return dll;
    }

    return {};
}

int main(int argc, char* argv[]) {
    utility::ScopeGuard guard{[]() {
        std::system("pause");
    }};

    // Set up spdlog to sink to the console
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] [cmdline-standalone] %v");
    spdlog::set_level(spdlog::level::info);
    spdlog::flush_on(spdlog::level::info);
    spdlog::set_default_logger(spdlog::stdout_logger_mt("console"));

    SPDLOG_INFO("Test!");

    // Convert args to a vector
    std::vector<std::string> args{};
    for (int i = 0; i < argc; i++) {
        args.push_back(argv[i]);
    }

    // if our args are less than 2, default to loading the "AlanWake2.exe" in the CWD
    std::filesystem::path path{};

    if (args.size() < 2) {
        path = std::filesystem::current_path() / "AlanWake2.exe";
    } else {
        path = args[1];
    }

    if (!std::filesystem::exists(path)) {
        SPDLOG_ERROR("File \"{}\" does not exist, cannot patch", path.string());
        SPDLOG_INFO("Usage: {} [path to AlanWake2.exe]", args[0]);
        SPDLOG_INFO("Or drag and drop AlanWake2.exe onto this executable");
        return 1;
    }

    SPDLOG_INFO("Attempting to patch \"{}\"...", path.string());

    const auto patched_bytes = get_patched_bytes(path);

    if (patched_bytes.empty()) {
        SPDLOG_ERROR("Failed to patch \"{}\"", path.string());
        return 1;
    }

    {
        SPDLOG_INFO("Writing patched bytes to \"{}\"", path.string());
        std::ofstream patched{path, std::ios::binary};

        if (!patched) {
            SPDLOG_ERROR("Failed to open \"{}\" for writing", path.string());
            SPDLOG_ERROR("Aborting patching process");
            return 1;
        }

        patched.write((char*)patched_bytes.data(), patched_bytes.size());
    }

    SPDLOG_INFO("Test finished!");

    return 0;
}
