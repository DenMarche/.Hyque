#include "ir.hpp"
#include <capstone/capstone.h>
#include <cstring>

namespace opr {
namespace {
constexpr uint8_t MaxX86Operands = 8;
}

namespace {
bool IsFlagWritingMnemonic(const std::string& M) {
    static const char* Ops[] = {
        "add", "sub", "cmp", "and", "or", "xor", "test", "inc", "dec", "neg",
        "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr", "mul",
        "imul", "div", "idiv", "adc", "sbb", "bt", "bts", "btr", "btc", "bsf",
        "bsr", "popcnt", "lzcnt", "tzcnt", "cmpxchg", "xadd",
    };
    for (const char* O : Ops) {
        if (M == O) return true;
    }
    return false;
}

bool IsConditionalJumpMnemonic(const std::string& M) {
    static const char* Cond[] = {
        "jo", "jno", "jb", "jnae", "jc", "jnb", "jae", "jnc", "je", "jz",
        "jne", "jnz", "jbe", "jna", "ja", "jnbe", "js", "jns", "jp", "jpe",
        "jnp", "jpo", "jl", "jnge", "jge", "jnl", "jle", "jng", "jg", "jnle",
        "jcxz", "jecxz", "jrcxz",
    };
    for (const char* C : Cond) {
        if (M == C) return true;
    }
    return false;
}

bool IsUnconditionalJumpMnemonic(const std::string& M) {
    return M == "jmp" || M == "ljmp";
}

bool IsRetMnemonic(const std::string& M) {
    return M == "ret" || M == "retf" || M == "retn" || M == "iret" || M == "iretd" || M == "iretq";
}

bool IsCallMnemonic(const std::string& M) {
    return M == "call" || M == "lcall";
}

Operand ConvertOperand(const cs_x86_op& op) {
    Operand Out;
    Out.Size = op.size;
    switch (op.type) {
    case X86_OP_REG:
        Out.Kind = OpKind::Reg;
        Out.Reg = (int)op.reg;
        break;
    case X86_OP_IMM:
        Out.Kind = OpKind::Imm;
        Out.Imm = (uint64_t)op.imm;
        break;
    case X86_OP_MEM:
        Out.Kind = OpKind::Mem;
        Out.Base = (int)op.mem.base;
        Out.Index = (int)op.mem.index;
        Out.Scale = op.mem.scale;
        Out.Disp = op.mem.disp;
        break;
    default:
        Out.Kind = OpKind::Invalid;
        break;
    }
    return Out;
}

}

bool Disassembler::Init(bool X64) {
    Close();
    csh H = 0;
    const cs_mode Mode = X64 ? CS_MODE_64 : CS_MODE_32;
    LastError = (int)cs_open(CS_ARCH_X86, Mode, &H);
    if (LastError != CS_ERR_OK) return false;

    if (cs_option(H, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&H);
        LastError = (int)CS_ERR_DIET;
        return false;
    }
    Handle = H;
    Detail = true;
    return true;
}

void Disassembler::Close() {
    if (Handle) {
        cs_close(&Handle);
        Handle = 0;
    }
    Detail = false;
}

std::string Disassembler::RegName(int Reg) const {
    if (!Reg || !Handle) return std::string();
    const char* N = cs_reg_name(Handle, (unsigned)Reg);
    return N ? std::string(N) : std::string();
}

std::vector<Insn> Disassembler::Disassemble(uint64_t BaseAddress,
                                           uint32_t RvaBase,
                                           const uint8_t* Code,
                                           size_t Size,
                                           size_t Count) {
    std::vector<Insn> Out;
    if (!Handle || !Code || Size == 0) return Out;
    const size_t Hint = Size / 6 + 64;
    Out.reserve(Hint > 4000000 ? 4000000 : Hint);
    cs_insn* Ci = cs_malloc(Handle);
    if (!Ci) return Out;
    const uint8_t* const end = Code + Size;
    const uint8_t* P = Code;
    uint64_t Addr = BaseAddress;
    size_t Remaining = Size;
    size_t Skipped = 0;
    const size_t SkipBudget = Size / 8 + 64;
    while (Remaining > 0) {
        if (Count && Out.size() >= Count) break;
        if (!cs_disasm_iter(Handle, &P, &Remaining, &Addr, Ci)) {
            ++P;
            if (P >= end) break;
            Remaining = (size_t)(end - P);
            Addr = BaseAddress + (uint64_t)(P - Code);
            if (++Skipped > SkipBudget) break;
            continue;
        }
        if (P <= Code || P > end) break;
        Addr = BaseAddress + (uint64_t)(P - Code);
        if (Ci->size == 0 || Ci->size > 15) break;
        Insn In;
        In.Address = Ci->address;
        In.Rva = RvaBase + (uint32_t)(Ci->address - BaseAddress);
        In.Size = (uint8_t)Ci->size;
        if (Ci->mnemonic) In.Mnemonic = Ci->mnemonic;
        if (Ci->op_str) In.OpStr = Ci->op_str;
        if (Ci->bytes) {
            const size_t CopyBytes = Ci->size < sizeof(In.Bytes) ? Ci->size : sizeof(In.Bytes);
            memcpy(In.Bytes, Ci->bytes, CopyBytes);
        }
        In.IsConditionalJump = IsConditionalJumpMnemonic(In.Mnemonic);
        In.IsUnconditionalJump = IsUnconditionalJumpMnemonic(In.Mnemonic);
        In.IsCall = IsCallMnemonic(In.Mnemonic);
        In.IsRet = IsRetMnemonic(In.Mnemonic);
        In.IsInt3 = (In.Mnemonic == "int3");
        In.ModifiesFlags = IsFlagWritingMnemonic(In.Mnemonic);
        if (Detail && Ci->detail) {
            const cs_x86& X86 = Ci->detail->x86;
            uint8_t OpCount = X86.op_count;
            if (OpCount > MaxX86Operands) OpCount = MaxX86Operands;
            In.Operands.reserve(OpCount);
            for (uint8_t O = 0; O < OpCount; ++O) {
                In.Operands.push_back(ConvertOperand(X86.operands[O]));
            }
            if ((In.IsConditionalJump || In.IsUnconditionalJump) && OpCount >= 1) {
                const cs_x86_op& Last = X86.operands[OpCount - 1];
                if (Last.type == X86_OP_IMM) {
                    In.Target = (uint64_t)Last.imm;
                    In.HasTarget = true;
                }
            }
            In.WritesDestination = !In.IsConditionalJump && !In.IsUnconditionalJump &&
                                   !In.IsCall && !In.IsRet && !In.IsInt3 && OpCount >= 1 &&
                                   X86.operands[0].type == X86_OP_REG;
        }
        Out.push_back(std::move(In));
    }
    cs_free(Ci, 1);
    printf("\nSuccessfully disassembled %zu bytes", Size);
    return Out;
}
}
