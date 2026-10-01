#include "proc.hpp"
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace opr {
namespace {

constexpr DWORD AccessRights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
constexpr uint64_t PageSize = 0x1000;
constexpr uint64_t PageMask = PageSize - 1;
constexpr size_t MaxModules = 1024;

constexpr uint16_t MagicPe32 = 0x10B;
constexpr uint16_t MagicPe32Plus = 0x20B;

constexpr size_t DosLfanewOffset = 0x3C;
constexpr size_t DosHeaderReadSize = 0x200;
constexpr size_t DosProbeSize = 0x1000;

constexpr size_t NtNumSectionsOffset = 6;
constexpr size_t NtOptionalSizeOffset = 20;
constexpr size_t NtOptionalOffset = 24;

constexpr size_t OptSectionAlignment = 32;
constexpr size_t OptFileAlignment = 36;
constexpr size_t OptSizeOfImage = 56;
constexpr size_t OptSizeOfHeaders = 60;

constexpr size_t SectVirtualSize = 8;
constexpr size_t SectVirtualAddress = 12;
constexpr size_t SectSizeOfRawData = 16;
constexpr size_t SectPointerToRawData = 20;
constexpr size_t SectHeaderSize = 40;

constexpr uint32_t DefaultFileAlignment = 0x200;
constexpr uint32_t DefaultSectionAlignment = 0x1000;

uint16_t Rd16(const uint8_t* P) {
    return (uint16_t)(P[0] | (P[1] << 8));
}

uint32_t Rd32(const uint8_t* P) {
    return (uint32_t)P[0] | ((uint32_t)P[1] << 8) | ((uint32_t)P[2] << 16) | ((uint32_t)P[3] << 24);
}

void Wr32(uint8_t* P, uint32_t V) {
    P[0] = (uint8_t)(V & 0xFF);
    P[1] = (uint8_t)((V >> 8) & 0xFF);
    P[2] = (uint8_t)((V >> 16) & 0xFF);
    P[3] = (uint8_t)((V >> 24) & 0xFF);
}

uint32_t AlignUp(uint32_t Value, uint32_t Align) {
    if (Align == 0) return Value;
    return (Value + Align - 1) & ~(Align - 1);
}

std::string LowerAscii(const std::string& S) {
    std::string Out = S;
    for (char& C : Out) {
        if (C >= 'A' && C <= 'Z') C = (char)(C - 'A' + 'a');
    }
    return Out;
}

bool EndsWithNoCase(const std::string& S, const std::string& Suffix) {
    if (S.size() < Suffix.size()) return false;
    return LowerAscii(S.substr(S.size() - Suffix.size())) == LowerAscii(Suffix);
}

std::string StripExtension(const std::string& S, const std::string& Ext) {
    return S.size() >= Ext.size() && EndsWithNoCase(S, Ext) ? S.substr(0, S.size() - Ext.size()) : S;
}

std::string Narrow(const wchar_t* W) {
    if (!W || !*W) return std::string();
    const int Need = WideCharToMultiByte(CP_UTF8, 0, W, -1, nullptr, 0, nullptr, nullptr);
    if (Need <= 0) return std::string();
    std::string S((size_t)Need - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, W, -1, &S[0], Need, nullptr, nullptr);
    return S;
}

std::string BaseName(const std::string& Path) {
    const size_t P = Path.find_last_of("/\\");
    return P == std::string::npos ? Path : Path.substr(P + 1);
}

bool IsReadableProtection(DWORD Protect) {
    if (Protect & PAGE_GUARD) return false;
    if (Protect & PAGE_NOACCESS) return false;
    switch (Protect & 0xFF) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

std::vector<uint32_t> PidsNamed(const std::string& Name) {
    std::vector<uint32_t> Pids;
    const std::string Wanted = LowerAscii(BaseName(Name));
    const std::string WantedBare = StripExtension(Wanted, ".exe");

    const HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snap == INVALID_HANDLE_VALUE) return Pids;

    PROCESSENTRY32W Entry;
    ZeroMemory(&Entry, sizeof(Entry));
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snap, &Entry)) {
        do {
            const std::string Current = LowerAscii(Narrow(Entry.szExeFile));
            if (Current == Wanted || Current == WantedBare) Pids.push_back(Entry.th32ProcessID);
        } while (Process32NextW(Snap, &Entry));
    }
    CloseHandle(Snap);
    return Pids;
}

}

Process::~Process() {
    Detach();
}

void Process::Detach() {
    if (Handle) {
        CloseHandle(Handle);
        Handle = nullptr;
    }
    PidValue = 0;
    ProcessNameValue.clear();
}

bool Process::IsInputBinaryADLL(const std::string& Name) {
    if (Name.empty()) return false;
    return EndsWithNoCase(Name, ".dll");
}

std::vector<std::string> Process::ListProcesses() {
    std::vector<std::string> Out;
    const HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snap == INVALID_HANDLE_VALUE) return Out;

    PROCESSENTRY32W Entry;
    ZeroMemory(&Entry, sizeof(Entry));
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snap, &Entry)) {
        do {
            const std::string Name = Narrow(Entry.szExeFile);
            if (!Name.empty()) Out.push_back(Name);
        } while (Process32NextW(Snap, &Entry));
    }
    CloseHandle(Snap);
    std::sort(Out.begin(), Out.end());
    return Out;
}

bool Process::Attach(const std::string& ProcessName, std::string& Error) {
    Detach();

    const std::vector<uint32_t> Candidates = PidsNamed(ProcessName);
    if (Candidates.empty()) {
        Error = "Process not found: " + ProcessName;
        return false;
    }
    if (Candidates.size() > 1) {
        fprintf(stderr, "%zu processes named %s, using PID %u. You can pass a PID to choose\n",
                Candidates.size(), ProcessName.c_str(), Candidates[0]);
    }

    const uint32_t Pid = Candidates[0];
    const HANDLE H = OpenProcess(AccessRights, FALSE, Pid);
    if (!H) {
        Error = "OpenProcess failed due to exception " + std::to_string(GetLastError()) +
                ". Try running elevated";
        return false;
    }
    Handle = H;
    PidValue = Pid;
    ProcessNameValue = ProcessName;
    return true;
}

bool Process::AttachPid(uint32_t Pid, std::string& Error) {
    Detach();

    const HANDLE H = OpenProcess(AccessRights, FALSE, Pid);
    if (!H) {
        Error = "Can't open PID " + std::to_string(Pid) + "due to exception " +
                std::to_string(GetLastError()) + ". Try running elevated";
        return false;
    }
    Handle = H;
    PidValue = Pid;
    ProcessNameValue = "PID:" + std::to_string(Pid);
    return true;
}

std::vector<ModuleInfo> Process::Modules() const {
    std::vector<ModuleInfo> Out;
    if (!Handle) return Out;

    HMODULE Mods[MaxModules];
    DWORD Needed = 0;
    if (!EnumProcessModulesEx(Handle, Mods, sizeof(Mods), &Needed, LIST_MODULES_ALL)) return Out;

    const DWORD Count = Needed / (DWORD)sizeof(HMODULE);
    for (DWORD I = 0; I < Count && I < MaxModules; ++I) {
        MODULEINFO Info;
        ZeroMemory(&Info, sizeof(Info));
        if (!GetModuleInformation(Handle, Mods[I], &Info, sizeof(Info))) continue;

        wchar_t PathBuf[MAX_PATH * 2];
        ZeroMemory(PathBuf, sizeof(PathBuf));
        GetModuleFileNameExW(Handle, Mods[I], PathBuf, (DWORD)(sizeof(PathBuf) / sizeof(wchar_t)));

        ModuleInfo M;
        M.Path = Narrow(PathBuf);
        M.Name = BaseName(M.Path);
        M.Base = (uintptr_t)Info.lpBaseOfDll;
        M.Size = Info.SizeOfImage;
        M.IsMain = (I == 0);
        if (M.Name.empty()) continue;
        Out.push_back(M);
    }
    return Out;
}

bool Process::FindModule(const std::string& Wanted, ModuleInfo& Out) const {
    const std::vector<ModuleInfo> Mods = Modules();
    if (Mods.empty()) return false;

    const std::string Want = LowerAscii(BaseName(Wanted));
    const std::string WantBare = StripExtension(StripExtension(Want, ".dll"), ".exe");

    for (const ModuleInfo& M : Mods) {
        if (LowerAscii(M.Name) == Want) {
            Out = M;
            return true;
        }
    }
    for (const ModuleInfo& M : Mods) {
        const std::string Lower = LowerAscii(M.Name);
        const size_t Dot = Lower.find_last_of('.');
        const std::string Stem = Dot == std::string::npos ? Lower : Lower.substr(0, Dot);
        if (Stem == Want || Stem == WantBare) {
            Out = M;
            return true;
        }
    }
    return false;
}

bool Process::MainModule(ModuleInfo& Out) const {
    const std::vector<ModuleInfo> Mods = Modules();
    for (const ModuleInfo& M : Mods) {
        if (M.IsMain) {
            Out = M;
            return true;
        }
    }
    if (Mods.empty()) return false;
    Out = Mods[0];
    return true;
}

bool Process::Read(uint64_t Address, size_t Size, std::vector<uint8_t>& Out) const {
    if (!Handle || Size == 0) return false;
    Out.assign(Size, 0);
    SIZE_T Got = 0;
    if (!ReadProcessMemory(Handle, (LPCVOID)(uintptr_t)Address, Out.data(), Size, &Got)) return false;
    return Got == Size;
}

size_t Process::ReadPartial(uint64_t Address, uint8_t* Dst, size_t Size) const {
    if (!Handle || !Dst || Size == 0) return 0;
    SIZE_T Got = 0;
    ReadProcessMemory(Handle, (LPCVOID)(uintptr_t)Address, Dst, Size, &Got);
    return (size_t)Got;
}

bool Process::ReadImage(const ModuleInfo& Mod, std::vector<uint8_t>& Out, std::string& Error,
                        uint64_t* Unreadable) const {
    if (!Mod.Base || Mod.Size == 0) {
        Error = "Module has no image";
        return false;
    }

    std::vector<uint8_t> Head(DosProbeSize, 0);
    if (ReadPartial(Mod.Base, Head.data(), Head.size()) < DosHeaderReadSize) {
        Error = "Can't read module headers at " + Mod.Name + "due to exception " +
                std::to_string(GetLastError()) + "";
        return false;
    }

    const uint32_t PeOff = Rd32(Head.data() + DosLfanewOffset);
    const uint8_t* Opt = Head.data() + PeOff + NtOptionalOffset;
    const uint16_t Magic = Rd16(Opt);
    uint32_t SizeOfImage = Rd32(Opt + OptSizeOfImage);
    if (Magic != MagicPe32 && Magic != MagicPe32Plus) SizeOfImage = 0;
    if (SizeOfImage == 0 || SizeOfImage > Mod.Size) SizeOfImage = Mod.Size;

    std::vector<uint8_t> Image(SizeOfImage, 0);
    uint64_t Missing = 0;
    uint64_t Offset = 0;
    while (Offset < SizeOfImage) {
        const uint64_t Address = Mod.Base + Offset;
        MEMORY_BASIC_INFORMATION Mbi;
        ZeroMemory(&Mbi, sizeof(Mbi));

        if (VirtualQueryEx(Handle, (LPCVOID)(uintptr_t)Address, &Mbi, sizeof(Mbi)) == 0) {
            uint64_t Skip = PageSize - (Offset & PageMask);
            if (Skip == 0) Skip = PageSize;
            if (Offset + Skip > SizeOfImage) Skip = SizeOfImage - Offset;
            Missing += Skip;
            Offset += Skip;
            continue;
        }

        const uint64_t RegionStartRel = (uint64_t)(uintptr_t)Mbi.BaseAddress - Mod.Base;
        if (RegionStartRel > SizeOfImage) {
            Missing += SizeOfImage - Offset;
            Offset = SizeOfImage;
            continue;
        }

        uint64_t SpanEnd = RegionStartRel + Mbi.RegionSize;
        if (SpanEnd > SizeOfImage) SpanEnd = SizeOfImage;
        if (SpanEnd <= Offset) {
            Missing += PageSize;
            Offset += PageSize;
            continue;
        }

        if (Mbi.State == MEM_COMMIT && IsReadableProtection(Mbi.Protect)) {
            const size_t Want = (size_t)(SpanEnd - Offset);
            const size_t Got = ReadPartial(Address, Image.data() + Offset, Want);
            if (Got < Want) Missing += (uint64_t)(Want - Got);
        } else {
            Missing += SpanEnd - Offset;
        }
        Offset = SpanEnd;
    }

    if (Missing >= SizeOfImage) {
        Error = "No readable pages in " + Mod.Name;
        return false;
    }
    if (Unreadable) *Unreadable = Missing;
    Out.swap(Image);
    return true;
}

bool Process::RebuildPe(const std::vector<uint8_t>& Image, std::vector<uint8_t>& Out,
                        std::string& Error) {
    const uint32_t PeOff = Rd32(Image.data() + DosLfanewOffset);
    const uint16_t NumSections = Rd16(Image.data() + PeOff + NtNumSectionsOffset);
    const uint16_t OptSize = Rd16(Image.data() + PeOff + NtOptionalSizeOffset);
    const size_t OptOff = (size_t)PeOff + NtOptionalOffset;
    if (OptOff + OptSize > Image.size()) {
        Error = "Optional header out of range";
        return false;
    }

    const uint16_t Magic = Rd16(Image.data() + OptOff);
    uint32_t FileAlignment = 0;
    uint32_t SectionAlignment = 0;
    if (Magic == MagicPe32Plus || Magic == MagicPe32) {
        SectionAlignment = Rd32(Image.data() + OptOff + OptSectionAlignment);
        FileAlignment = Rd32(Image.data() + OptOff + OptFileAlignment);
    }
    if (FileAlignment == 0) FileAlignment = DefaultFileAlignment;
    if (SectionAlignment == 0) SectionAlignment = DefaultSectionAlignment;

    const size_t SectTableOff = OptOff + OptSize;
    const size_t SizeOfHeadersRaw = SectTableOff + (size_t)NumSections * SectHeaderSize;
    if (SizeOfHeadersRaw > Image.size()) {
        Error = "Section table out of range";
        return false;
    }

    const uint32_t SizeOfHeaders = AlignUp((uint32_t)SizeOfHeadersRaw, FileAlignment);
    uint32_t Cursor = SizeOfHeaders;

    std::vector<uint32_t> RawPtr(NumSections, 0);
    std::vector<uint32_t> RawSize(NumSections, 0);
    for (uint16_t I = 0; I < NumSections; ++I) {
        const uint8_t* S = Image.data() + SectTableOff + (size_t)I * SectHeaderSize;
        const uint32_t Va = Rd32(S + SectVirtualAddress);
        const uint32_t VSize = Rd32(S + SectVirtualSize);
        const uint32_t VSizeEff = VSize ? VSize : Rd32(S + SectSizeOfRawData);

        const uint64_t End =
            (uint64_t)Va + VSizeEff > Image.size() ? Image.size() : (uint64_t)Va + VSizeEff;
        const uint32_t Take = (uint64_t)Va < Image.size() ? (uint32_t)(End - Va) : 0;

        RawPtr[I] = Take ? Cursor : 0;
        RawSize[I] = Take ? AlignUp(Take, FileAlignment) : 0;
        if (RawSize[I]) Cursor += RawSize[I];
    }

    Out.assign(Cursor, 0);
    memcpy(Out.data(), Image.data(), SizeOfHeaders > Image.size() ? Image.size() : SizeOfHeaders);
    if (SizeOfHeaders > Image.size()) {
        memset(Out.data() + Image.size(), 0, SizeOfHeaders - Image.size());
    }
    Wr32(Out.data() + OptOff + OptSizeOfHeaders, SizeOfHeaders);

    for (uint16_t I = 0; I < NumSections; ++I) {
        uint8_t* S = Out.data() + SectTableOff + (size_t)I * SectHeaderSize;
        Wr32(S + SectSizeOfRawData, RawSize[I]);
        Wr32(S + SectPointerToRawData, RawPtr[I]);
    }

    for (uint16_t I = 0; I < NumSections; ++I) {
        if (!RawPtr[I] || !RawSize[I]) continue;
        const uint8_t* S = Image.data() + SectTableOff + (size_t)I * SectHeaderSize;
        const uint32_t Va = Rd32(S + SectVirtualAddress);
        const uint32_t VSize = Rd32(S + SectVirtualSize);
        const uint32_t VSizeEff = VSize ? VSize : Rd32(S + SectSizeOfRawData);

        const uint64_t End =
            (uint64_t)Va + VSizeEff > Image.size() ? Image.size() : (uint64_t)Va + VSizeEff;
        if ((uint64_t)Va >= Image.size()) continue;
        const uint32_t Take = (uint32_t)(End - Va);
        if ((uint64_t)RawPtr[I] + Take > Out.size()) continue;
        memcpy(Out.data() + RawPtr[I], Image.data() + Va, Take);
    }
    return true;
}

bool Process::WriteFile(const std::string& Path, const std::vector<uint8_t>& Bytes) {
    std::ofstream F(Path, std::ios::binary | std::ios::trunc);
    if (!F) return false;
    if (!Bytes.empty()) F.write((const char*)Bytes.data(), (std::streamsize)Bytes.size());
    F.flush();
    return (bool)F;
}

}