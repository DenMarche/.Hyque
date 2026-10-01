#include "regs.hpp"
#include <capstone/x86.h>

namespace opr {
namespace {

struct RegEntry {
    unsigned CsRegId;
    int Canonical;
    unsigned ByteOffset;
    unsigned ByteSize;
};

RegisterView Make(int Canonical, unsigned ByteOffset, unsigned ByteSize) {
    RegisterView View;
    View.Canonical = Canonical;
    View.ByteOffset = (uint8_t)ByteOffset;
    View.ByteSize = (uint8_t)ByteSize;
    return View;
}

const RegEntry RegTable[] = {
    {X86_REG_RAX, 0, 0, 8}, {X86_REG_RCX, 1, 0, 8}, {X86_REG_RDX, 2, 0, 8},
    {X86_REG_RBX, 3, 0, 8}, {X86_REG_RSP, 4, 0, 8}, {X86_REG_RBP, 5, 0, 8},
    {X86_REG_RSI, 6, 0, 8}, {X86_REG_RDI, 7, 0, 8}, {X86_REG_R8, 8, 0, 8},
    {X86_REG_R9, 9, 0, 8},  {X86_REG_R10, 10, 0, 8}, {X86_REG_R11, 11, 0, 8},
    {X86_REG_R12, 12, 0, 8}, {X86_REG_R13, 13, 0, 8}, {X86_REG_R14, 14, 0, 8},
    {X86_REG_R15, 15, 0, 8},

    {X86_REG_EAX, 0, 0, 4}, {X86_REG_ECX, 1, 0, 4}, {X86_REG_EDX, 2, 0, 4},
    {X86_REG_EBX, 3, 0, 4}, {X86_REG_ESP, 4, 0, 4}, {X86_REG_EBP, 5, 0, 4},
    {X86_REG_ESI, 6, 0, 4}, {X86_REG_EDI, 7, 0, 4}, {X86_REG_R8D, 8, 0, 4},
    {X86_REG_R9D, 9, 0, 4}, {X86_REG_R10D, 10, 0, 4}, {X86_REG_R11D, 11, 0, 4},
    {X86_REG_R12D, 12, 0, 4}, {X86_REG_R13D, 13, 0, 4}, {X86_REG_R14D, 14, 0, 4},
    {X86_REG_R15D, 15, 0, 4},

    {X86_REG_AX, 0, 0, 2}, {X86_REG_CX, 1, 0, 2}, {X86_REG_DX, 2, 0, 2},
    {X86_REG_BX, 3, 0, 2}, {X86_REG_SP, 4, 0, 2}, {X86_REG_BP, 5, 0, 2},
    {X86_REG_SI, 6, 0, 2}, {X86_REG_DI, 7, 0, 2}, {X86_REG_R8W, 8, 0, 2},
    {X86_REG_R9W, 9, 0, 2}, {X86_REG_R10W, 10, 0, 2}, {X86_REG_R11W, 11, 0, 2},
    {X86_REG_R12W, 12, 0, 2}, {X86_REG_R13W, 13, 0, 2}, {X86_REG_R14W, 14, 0, 2},
    {X86_REG_R15W, 15, 0, 2},

    {X86_REG_AL, 0, 0, 1}, {X86_REG_CL, 1, 0, 1}, {X86_REG_DL, 2, 0, 1},
    {X86_REG_BL, 3, 0, 1}, {X86_REG_SPL, 4, 0, 1}, {X86_REG_BPL, 5, 0, 1},
    {X86_REG_SIL, 6, 0, 1}, {X86_REG_DIL, 7, 0, 1}, {X86_REG_R8B, 8, 0, 1},
    {X86_REG_R9B, 9, 0, 1}, {X86_REG_R10B, 10, 0, 1}, {X86_REG_R11B, 11, 0, 1},
    {X86_REG_R12B, 12, 0, 1}, {X86_REG_R13B, 13, 0, 1}, {X86_REG_R14B, 14, 0, 1},
    {X86_REG_R15B, 15, 0, 1},

    {X86_REG_AH, 0, 1, 1}, {X86_REG_CH, 1, 1, 1}, {X86_REG_DH, 2, 1, 1},
    {X86_REG_BH, 3, 1, 1},
};

}

RegisterView RegView(unsigned CsRegId) {
    for (const RegEntry& Entry : RegTable) {
        if (Entry.CsRegId == CsRegId) {
            return Make(Entry.Canonical, Entry.ByteOffset, Entry.ByteSize);
        }
    }
    return Make(-1, 0, 0);
}

unsigned BitWidthFor(unsigned ByteSize) {
    switch (ByteSize) {
    case 1: return 8;
    case 2: return 16;
    case 4: return 32;
    case 8: return 64;
    default: return 0;
    }
}

uint64_t SizeMaskFor(unsigned ByteSize) {
    const unsigned Bits = BitWidthFor(ByteSize);
    if (Bits == 0 || Bits >= 64) return ~0ULL;
    return (1ULL << Bits) - 1ULL;
}

uint64_t SignExtend(uint64_t Value, unsigned ByteSize) {
    const unsigned Bits = BitWidthFor(ByteSize);
    if (Bits == 0 || Bits >= 64) return Value;
    const uint64_t SignBit = 1ULL << (Bits - 1);
    if (Value & SignBit) return Value | ~((1ULL << Bits) - 1ULL);
    return Value;
}

}