#include "pe.hpp"
#include <cstring>

namespace opr {
namespace {

constexpr uint16_t DosSignature = 0x5A4D;
constexpr uint32_t NtSignature = 0x00004550;
constexpr uint16_t MagicPe32 = 0x10B;
constexpr uint16_t MagicPe32Plus = 0x20B;

constexpr size_t DosHeaderSize = 0x40;
constexpr size_t DosLfanewOffset = 0x3C;

constexpr size_t NtNumSectionsOffset = 6;
constexpr size_t NtOptionalSizeOffset = 20;
constexpr size_t NtOptionalOffset = 24;
constexpr size_t NtSignatureOffset = 0;

constexpr size_t OptAddressOfEntryPoint = 16;

constexpr size_t SectVirtualSize = 8;
constexpr size_t SectVirtualAddress = 12;
constexpr size_t SectSizeOfRawData = 16;
constexpr size_t SectPointerToRawData = 20;
constexpr size_t SectCharacteristics = 36;
constexpr size_t SectHeaderSize = 40;
constexpr size_t SectNameSize = 8;

uint16_t Rd16(const uint8_t* P) {
    return (uint16_t)(P[0] | (P[1] << 8));
}

uint32_t Rd32(const uint8_t* P) {
    return (uint32_t)P[0] | ((uint32_t)P[1] << 8) | ((uint32_t)P[2] << 16) | ((uint32_t)P[3] << 24);
}

uint64_t Rd64(const uint8_t* P) {
    return (uint64_t)Rd32(P) | ((uint64_t)Rd32(P + 4) << 32);
}

}

bool PE::LoadFromMemory(const uint8_t* Data, size_t Size) {
    if (Size < DosHeaderSize) return false;
    if (Rd16(Data) != DosSignature) return false;

    const uint32_t PeOff = Rd32(Data + DosLfanewOffset);
    if ((uint64_t)PeOff + NtOptionalOffset > Size) return false;

    const uint8_t* Nt = Data + PeOff;
    if (Rd32(Nt + NtSignatureOffset) != NtSignature) return false;

    const uint16_t NumSections = Rd16(Nt + NtNumSectionsOffset);
    const uint16_t OptSize = Rd16(Nt + NtOptionalSizeOffset);
    const uint8_t* Opt = Nt + NtOptionalOffset;
    if ((uint64_t)(Opt - Data) + OptSize > Size) return false;

    const uint16_t Magic = Rd16(Opt);
    if (Magic == MagicPe32Plus) {
        Is64Bit = true;
        EntryRvaValue = Rd32(Opt + OptAddressOfEntryPoint);
    } else if (Magic == MagicPe32) {
        Is64Bit = false;
        EntryRvaValue = Rd32(Opt + OptAddressOfEntryPoint);
    } else {
        return false;
    }

    const uint8_t* SectTable = Opt + OptSize;
    SectionList.clear();
    for (uint16_t I = 0; I < NumSections; ++I) {
        const uint64_t Off = (uint64_t)(SectTable - Data) + (uint64_t)I * SectHeaderSize;
        if (Off + SectHeaderSize > Size) break;

        const uint8_t* S = Data + Off;
        char Name[SectNameSize + 1] = {0};
        memcpy(Name, S, SectNameSize);

        Section Sec;
        Sec.Name = Name;
        Sec.VirtualSize = Rd32(S + SectVirtualSize);
        Sec.VirtualAddress = Rd32(S + SectVirtualAddress);
        Sec.RawSize = Rd32(S + SectSizeOfRawData);
        Sec.RawOffset = Rd32(S + SectPointerToRawData);
        Sec.Characteristics = Rd32(S + SectCharacteristics);
        SectionList.push_back(Sec);
    }

    ImageData.assign(Data, Data + Size);
    return !SectionList.empty();
}

bool PE::RvaToOffset(uint64_t Rva, uint64_t& Offset) const {
    for (const Section& S : SectionList) {
        const uint64_t Span = S.VirtualSize ? S.VirtualSize : S.RawSize;
        if (Rva < S.VirtualAddress || Rva >= S.VirtualAddress + Span) continue;

        const uint64_t Delta = Rva - S.VirtualAddress;
        if (Delta >= S.RawSize) return false;

        Offset = (uint64_t)S.RawOffset + Delta;
        return Offset < ImageData.size();
    }
    return false;
}

bool PE::ReadRva(uint64_t Rva, size_t Size, std::vector<uint8_t>& Out) const {
    uint64_t Off = 0;
    if (!RvaToOffset(Rva, Off)) return false;
    if (Off + Size > ImageData.size()) return false;
    Out.assign(ImageData.begin() + (size_t)Off, ImageData.begin() + (size_t)(Off + Size));
    return true;
}

bool PE::FindCodeSection(Section& Out) const {
    for (const Section& S : SectionList) {
        if (S.Name == ".text") {
            Out = S;
            return true;
        }
    }
    for (const Section& S : SectionList) {
        if (S.Executable() && S.RawSize) {
            Out = S;
            return true;
        }
    }
    return false;
}

bool PE::FindNamedSection(const std::string& Name, Section& Out) const {
    for (const Section& S : SectionList) {
        if (S.Name == Name) {
            Out = S;
            return true;
        }
    }
    return false;
}

}