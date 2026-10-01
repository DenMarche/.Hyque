#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace opr {

constexpr uint32_t ImageScnMemExecute = 0x20000000u;
constexpr uint32_t ImageScnMemRead = 0x40000000u;

struct Section {
    std::string Name;
    uint32_t VirtualAddress = 0;
    uint32_t VirtualSize = 0;
    uint32_t RawOffset = 0;
    uint32_t RawSize = 0;
    uint32_t Characteristics = 0;
    bool Executable() const { return (Characteristics & ImageScnMemExecute) != 0; }
    bool Readable() const { return (Characteristics & ImageScnMemRead) != 0; }
};

class PE {
public:
    bool LoadFromMemory(const uint8_t* Data, size_t Size);
    bool Is64() const { return Is64Bit; }
    uint32_t EntryRva() const { return EntryRvaValue; }
    bool RvaToOffset(uint64_t Rva, uint64_t& Offset) const;
    bool ReadRva(uint64_t Rva, size_t Size, std::vector<uint8_t>& Out) const;
    bool FindCodeSection(Section& Out) const;
    bool FindNamedSection(const std::string& Name, Section& Out) const;
private:
    std::vector<uint8_t> ImageData;
    std::vector<Section> SectionList;
    uint32_t EntryRvaValue = 0;
    bool Is64Bit = false;
};

}