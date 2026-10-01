#pragma once
#include <capstone/capstone.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace opr {
enum class OpKind { Invalid, Reg, Imm, Mem };

struct Operand {
    OpKind Kind = OpKind::Invalid;
    int Reg = 0;
    uint64_t Imm = 0;
    int Base = 0;
    int Index = 0;
    int Scale = 0;
    int64_t Disp = 0;
    uint8_t Size = 0;
};

struct Insn {
    uint64_t Address = 0;
    uint32_t Rva = 0;
    uint8_t Size = 0;
    std::string Mnemonic;
    std::string OpStr;
    uint8_t Bytes[16] = {0};
    std::vector<Operand> Operands;
    bool IsConditionalJump = false;
    bool IsUnconditionalJump = false;
    bool IsCall = false;
    bool IsRet = false;
    bool IsInt3 = false;
    bool ModifiesFlags = false;
    bool WritesDestination = false;
    uint64_t Target = 0;
    bool HasTarget = false;
};

class Disassembler {
public:
    bool Init(bool X64);
    void Close();
    bool Valid() const { return Handle != 0; }
    int LastError = 0;
    std::vector<Insn> Disassemble(uint64_t BaseAddress, uint32_t RvaBase, const uint8_t* Code,
                                  size_t Size, size_t Count = 0);
    std::string RegName(int Reg) const;
private:
    csh Handle = 0;
    bool Detail = false;
};
}
