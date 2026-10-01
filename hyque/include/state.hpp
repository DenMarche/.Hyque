#pragma once
#include "ir.hpp"
#include "regs.hpp"
#include <array>
#include <cstdint>
#include <map>

namespace opr {
struct AbsVal {
    bool Known = false;
    uint64_t V = 0;
    static AbsVal Top() { return AbsVal{false, 0}; }
    static AbsVal Con(uint64_t X) { return AbsVal{true, X}; }
    bool IsTop() const { return !Known; }
    explicit operator bool() const { return Known; }
};

struct Flags {
    AbsVal Cf, Pf, Af, Zf, Sf, Of;
    void MakeTop();
    void ClearAll();
    bool AllKnown() const {
        return Cf.Known && Pf.Known && Zf.Known && Sf.Known && Of.Known;
    }
};

struct State {
    std::array<AbsVal, 16> Regs{};
    Flags Flags;
    void MakeTop();
    AbsVal Read(const RegisterView& Rv) const;
    void write(const RegisterView& Rv, AbsVal Val);
    AbsVal ReadOperand(const Operand& op) const;
    void WriteOperand(const Operand& op, AbsVal Val);
};
void StepInstruction(const Insn& In, State& St, Disassembler& dis);
int EvalCondition(const std::string& Mnemonic, const State& St, std::string* Why = nullptr);
}
