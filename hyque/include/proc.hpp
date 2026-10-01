#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace opr {

struct ModuleInfo {
    std::string Name;
    std::string Path;
    uintptr_t Base = 0;
    uint32_t Size = 0;
    bool IsMain = false;
};

class Process {
public:
    Process() = default;
    ~Process();
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    bool Attach(const std::string& ProcessName, std::string& Error);
    bool AttachPid(uint32_t Pid, std::string& Error);
    void Detach();

    uint32_t Pid() const { return PidValue; }
    const std::string& ProcessName() const { return ProcessNameValue; }

    std::vector<ModuleInfo> Modules() const;
    bool FindModule(const std::string& Wanted, ModuleInfo& Out) const;
    bool MainModule(ModuleInfo& Out) const;

    bool Read(uint64_t Address, size_t Size, std::vector<uint8_t>& Out) const;
    size_t ReadPartial(uint64_t Address, uint8_t* Dst, size_t Size) const;
    bool ReadImage(const ModuleInfo& Mod, std::vector<uint8_t>& Out, std::string& Error,
                   uint64_t* Unreadable) const;

    static std::vector<std::string> ListProcesses();
    static bool IsInputBinaryADLL(const std::string& Name);
    static bool WriteFile(const std::string& Path, const std::vector<uint8_t>& Bytes);
    static bool RebuildPe(const std::vector<uint8_t>& Image, std::vector<uint8_t>& Out,
                          std::string& Error);

private:
    HANDLE Handle = nullptr;
    uint32_t PidValue = 0;
    std::string ProcessNameValue;
};

}