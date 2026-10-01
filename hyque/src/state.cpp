#include "state.hpp"
#include <capstone/x86.h>
#include <cstdio>
#include <cstring>

namespace opr {
namespace {
uint64_t ParityOf(uint64_t R) {
    uint8_t B = (uint8_t)(R & 0xFF);
    B = (uint8_t)(B ^ (B >> 4));
    B = (uint8_t)(B ^ (B >> 2));
    B = (uint8_t)(B ^ (B >> 1));
    return (B & 1) ? 0ULL : 1ULL;
}

void SetAddFlags(Flags& F, uint64_t A, uint64_t B, uint64_t R, unsigned Width) {
    const uint64_t Mask = SizeMaskFor(Width);
    const uint64_t Ua = A & Mask, Ub = B & Mask, ur = R & Mask;
    const unsigned Bits = BitWidthFor(Width);
    if (Bits == 0) return;
    const uint64_t SignBit = 1ULL << (Bits - 1);
    F.Zf = AbsVal::Con(ur == 0 ? 1 : 0);
    F.Sf = AbsVal::Con((ur & SignBit) ? 1 : 0);
    F.Pf = AbsVal::Con(ParityOf(ur));
    F.Af = AbsVal::Top();
    F.Cf = AbsVal::Con((Ua + Ub) > Mask ? 1 : 0);
    F.Of = AbsVal::Con((((~(Ua ^ Ub)) & (Ua ^ ur)) & SignBit) ? 1 : 0);
}

void SetSubFlags(Flags& F, uint64_t A, uint64_t B, uint64_t R, unsigned Width) {
    const uint64_t Mask = SizeMaskFor(Width);
    const uint64_t Ua = A & Mask, Ub = B & Mask, ur = R & Mask;
    const unsigned Bits = BitWidthFor(Width);
    if (Bits == 0) return;
    const uint64_t SignBit = 1ULL << (Bits - 1);
    F.Zf = AbsVal::Con(ur == 0 ? 1 : 0);
    F.Sf = AbsVal::Con((ur & SignBit) ? 1 : 0);
    F.Pf = AbsVal::Con(ParityOf(ur));
    F.Af = AbsVal::Top();
    F.Cf = AbsVal::Con(Ua < Ub ? 1 : 0);
    F.Of = AbsVal::Con((((Ua ^ Ub) & (Ua ^ ur)) & SignBit) ? 1 : 0);
}

void SetLogicFlags(Flags& F, uint64_t R, unsigned Width) {
    const uint64_t Mask = SizeMaskFor(Width);
    const uint64_t ur = R & Mask;
    const unsigned Bits = BitWidthFor(Width);
    if (Bits == 0) return;
    const uint64_t SignBit = 1ULL << (Bits - 1);
    F.Cf = AbsVal::Con(0);
    F.Of = AbsVal::Con(0);
    F.Af = AbsVal::Top();
    F.Zf = AbsVal::Con(ur == 0 ? 1 : 0);
    F.Sf = AbsVal::Con((ur & SignBit) ? 1 : 0);
    F.Pf = AbsVal::Con(ParityOf(ur));
}

int TriAnd(int A, int B) {
    if (A == 0 || B == 0) return 0;
    if (A == 1 && B == 1) return 1;
    return -1;
}

int TriOr(int A, int B) {
    if (A == 1 || B == 1) return 1;
    if (A == 0 && B == 0) return 0;
    return -1;
}

int FlagIs(const AbsVal& F) {
    return F.Known ? (int)(F.V & 1ULL) : -1;
}

int FlagIsNot(const AbsVal& F) {
    return F.Known ? ((F.V & 1ULL) ? 0 : 1) : -1;
}

int SfNeOf(const Flags& F) {
    if (!F.Sf.Known || !F.Of.Known) return -1;
    return ((F.Sf.V & 1ULL) != (F.Of.V & 1ULL)) ? 1 : 0;
}

int SfEqOf(const Flags& F) {
    if (!F.Sf.Known || !F.Of.Known) return -1;
    return ((F.Sf.V & 1ULL) == (F.Of.V & 1ULL)) ? 1 : 0;
}

unsigned WidthOf(const Insn& In) {
    for (const Operand& O : In.Operands) {
        if (O.Size == 1 || O.Size == 2 || O.Size == 4 || O.Size == 8) return O.Size;
    }
    return 0;
}

bool StartsWith(const std::string& S, const char* P) {
    const size_t N = strlen(P);
    return S.size() >= N && memcmp(S.data(), P, N) == 0;
}

void SetRegTop(State& St, int Canon) {
    if (Canon >= 0 && Canon < 16) St.Regs[(size_t)Canon] = AbsVal::Top();
}

}

void Flags::MakeTop() {
    Cf = Pf = Af = Zf = Sf = Of = AbsVal::Top();
}

void Flags::ClearAll() {
    Cf = Pf = Af = Zf = Sf = Of = AbsVal::Con(0);
}

void State::MakeTop() {
    for (AbsVal& R : Regs) R = AbsVal::Top();
    Flags.MakeTop();
}

AbsVal State::Read(const RegisterView& Rv) const {
    if (Rv.Canonical < 0 || Rv.Canonical > 15 || Rv.ByteSize == 0) return AbsVal::Top();
    const AbsVal& Base = Regs[(size_t)Rv.Canonical];
    if (Base.IsTop()) return AbsVal::Top();
    return AbsVal::Con((Base.V >> (Rv.ByteOffset * 8)) & SizeMaskFor(Rv.ByteSize));
}

void State::write(const RegisterView& Rv, AbsVal Val) {
    if (Rv.Canonical < 0 || Rv.Canonical > 15 || Rv.ByteSize == 0) return;
    if (Rv.ByteSize == 8) {
        Regs[(size_t)Rv.Canonical] = Val;
        return;
    }
    if (Rv.ByteSize == 4) {
        Regs[(size_t)Rv.Canonical] =
            Val.IsTop() ? AbsVal::Top() : AbsVal::Con(Val.V & 0xFFFFFFFFULL);
        return;
    }
    const uint64_t PartMask = SizeMaskFor(Rv.ByteSize) << (Rv.ByteOffset * 8);
    AbsVal& Base = Regs[(size_t)Rv.Canonical];
    if (Val.IsTop() || Base.IsTop()) {
        Base = AbsVal::Top();
        return;
    }
    Base = AbsVal::Con((Base.V & ~PartMask) | ((Val.V << (Rv.ByteOffset * 8)) & PartMask));
}

AbsVal State::ReadOperand(const Operand& op) const {
    switch (op.Kind) {
    case OpKind::Imm:
        return AbsVal::Con(op.Imm);
    case OpKind::Reg:
        return Read(RegView((unsigned)op.Reg));
    case OpKind::Mem:
    default:
        return AbsVal::Top();
    }
}

void State::WriteOperand(const Operand& op, AbsVal Val) {
    if (op.Kind != OpKind::Reg) return;
    write(RegView((unsigned)op.Reg), Val);
}

void StepInstruction(const Insn& In, State& St, Disassembler& dis) {
    (void)dis;
    const std::string& M = In.Mnemonic;
    const auto& Ops = In.Operands;
    if (In.IsConditionalJump || In.IsUnconditionalJump || In.IsCall || In.IsRet) return;
    if (In.IsInt3) return;
    if (M == "nop" || M == "endbr64" || M == "endbr32" || M == "pause" || M == "lfence" ||
        M == "mfence" || M == "sfence" || M == "ud2" || M == "cld" || M == "std") {
        return;
    }
    if (M == "clc" || M == "stc" || M == "cmc") {
        if (M == "clc") St.Flags.Cf = AbsVal::Con(0);
        else if (M == "stc") St.Flags.Cf = AbsVal::Con(1);
        else St.Flags.Cf = AbsVal::Top();
        return;
    }
    if (M == "cwde" || M == "cdqe" || M == "cbw") {
        SetRegTop(St, 0);
        return;
    }
    if (M == "cdq" || M == "cqo" || M == "cwd" || M == "cdqe") {
        SetRegTop(St, 0);
        SetRegTop(St, 2);
        return;
    }
    if (StartsWith(M, "nop")) return;
    if (M == "push" || StartsWith(M, "push")) {
        SetRegTop(St, 4);
        return;
    }
    if (M == "pop" || StartsWith(M, "pop")) {
        SetRegTop(St, 4);
        if (Ops.size() == 1 && Ops[0].Kind == OpKind::Reg) St.WriteOperand(Ops[0], AbsVal::Top());
        return;
    }
    if (M == "mov" || M == "movabs") {
        if (Ops.size() >= 2) St.WriteOperand(Ops[0], St.ReadOperand(Ops[1]));
        return;
    }
    if (M == "movzx") {
        if (Ops.size() >= 2) {
            AbsVal S = St.ReadOperand(Ops[1]);
            if (S.Known) S = AbsVal::Con(S.V & SizeMaskFor(Ops[1].Size));
            else S = AbsVal::Top();
            St.WriteOperand(Ops[0], S);
        }
        return;
    }
    if (M == "movsx" || M == "movsxd") {
        if (Ops.size() >= 2) {
            AbsVal S = St.ReadOperand(Ops[1]);
            St.WriteOperand(Ops[0],
                            S.Known ? AbsVal::Con(SignExtend(S.V & SizeMaskFor(Ops[1].Size),
                                                             Ops[1].Size))
                                    : AbsVal::Top());
        }
        return;
    }
    if (M == "lea") {
        if (Ops.size() >= 2 && Ops[0].Kind == OpKind::Reg && Ops[1].Kind == OpKind::Mem) {
            const Operand& mem = Ops[1];
            AbsVal Addr = AbsVal::Con((uint64_t)mem.Disp);
            const RegisterView Base = RegView((unsigned)mem.Base);
            const RegisterView idx = RegView((unsigned)mem.Index);
            if (Base.Canonical < 0 && (unsigned)mem.Base == X86_REG_RIP) {
                Addr = AbsVal::Con(In.Address + In.Size + (uint64_t)mem.Disp);
            } else if (Base.ByteSize && idx.ByteSize) {
                const AbsVal B = St.Read(Base);
                const AbsVal I = St.Read(idx);
                if (!B.Known || !I.Known) {
                    Addr = AbsVal::Top();
                } else {
                    Addr = AbsVal::Con(B.V + I.V * (uint64_t)mem.Scale + (uint64_t)mem.Disp);
                }
            } else if (Base.ByteSize) {
                const AbsVal B = St.Read(Base);
                Addr = B.Known ? AbsVal::Con(B.V + (uint64_t)mem.Disp) : AbsVal::Top();
            } else if (idx.ByteSize) {
                const AbsVal I = St.Read(idx);
                Addr = I.Known ? AbsVal::Con(I.V * (uint64_t)mem.Scale + (uint64_t)mem.Disp)
                               : AbsVal::Top();
            }
            St.WriteOperand(Ops[0], Addr);
        }
        return;
    }
    if (M == "xchg") {
        if (Ops.size() >= 2) {
            const AbsVal A = St.ReadOperand(Ops[0]);
            const AbsVal B = St.ReadOperand(Ops[1]);
            St.WriteOperand(Ops[0], B);
            St.WriteOperand(Ops[1], A);
        }
        return;
    }
    const unsigned Width = WidthOf(In);
    const uint64_t Mask = SizeMaskFor(Width);
    if (M == "xor" || M == "and" || M == "or") {
        if (Ops.size() < 2 || Ops[0].Kind != OpKind::Reg) {
            St.Flags.MakeTop();
            return;
        }
        const RegisterView D = RegView((unsigned)Ops[0].Reg);
        const RegisterView S = (Ops[1].Kind == OpKind::Reg) ? RegView((unsigned)Ops[1].Reg)
                                                            : RegisterView{-1, 0, 0};
        const bool SameReg = (Ops[1].Kind == OpKind::Reg) &&
                             D.Canonical == S.Canonical && D.ByteSize == S.ByteSize &&
                             D.ByteOffset == S.ByteOffset;
        if (SameReg && M != "or") {
            St.write(D, AbsVal::Con(0));
            SetLogicFlags(St.Flags, 0, Width ? Width : D.ByteSize);
            return;
        }
        const AbsVal A = St.ReadOperand(Ops[0]);
        const AbsVal B = St.ReadOperand(Ops[1]);
        if (!A.Known || !B.Known) {
            St.write(D, AbsVal::Top());
            St.Flags.MakeTop();
            return;
        }
        uint64_t R;
        if (M == "xor") R = A.V ^ B.V;
        else if (M == "and") R = A.V & B.V;
        else R = A.V | B.V;
        R &= Mask;
        St.write(D, AbsVal::Con(R));
        SetLogicFlags(St.Flags, R, Width ? Width : D.ByteSize);
        return;
    }
    if (M == "test") {
        if (Ops.size() < 2) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        const AbsVal B = St.ReadOperand(Ops[1]);
        if (!A.Known || !B.Known) { St.Flags.MakeTop(); return; }
        SetLogicFlags(St.Flags, A.V & B.V, Width ? Width : Ops[0].Size);
        return;
    }
    if (M == "cmp") {
        if (Ops.size() < 2) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        const AbsVal B = St.ReadOperand(Ops[1]);
        if (!A.Known || !B.Known) { St.Flags.MakeTop(); return; }
        SetSubFlags(St.Flags, A.V, B.V, (A.V - B.V) & Mask, Width ? Width : Ops[0].Size);
        return;
    }
    if (M == "add" || M == "sub") {
        if (Ops.size() < 2 || Ops[0].Kind != OpKind::Reg) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        const AbsVal B = St.ReadOperand(Ops[1]);
        if (!A.Known || !B.Known) {
            St.WriteOperand(Ops[0], AbsVal::Top());
            St.Flags.MakeTop();
            return;
        }
        const uint64_t R = (M == "add") ? ((A.V + B.V) & Mask) : ((A.V - B.V) & Mask);
        St.WriteOperand(Ops[0], AbsVal::Con(R));
        if (M == "add") SetAddFlags(St.Flags, A.V, B.V, R, Width ? Width : Ops[0].Size);
        else SetSubFlags(St.Flags, A.V, B.V, R, Width ? Width : Ops[0].Size);
        return;
    }
    if (M == "inc" || M == "dec") {
        if (Ops.empty() || Ops[0].Kind != OpKind::Reg) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        if (!A.Known) { St.WriteOperand(Ops[0], AbsVal::Top()); St.Flags.MakeTop(); return; }
        const unsigned W = Width ? Width : Ops[0].Size;
        const uint64_t R = (M == "inc") ? ((A.V + 1ULL) & SizeMaskFor(W))
                                        : ((A.V - 1ULL) & SizeMaskFor(W));
        St.WriteOperand(Ops[0], AbsVal::Con(R));
        const AbsVal SavedCf = St.Flags.Cf;
        if (M == "inc") SetAddFlags(St.Flags, A.V, 1ULL, R, W);
        else SetSubFlags(St.Flags, A.V, 1ULL, R, W);
        St.Flags.Cf = SavedCf;
        return;
    }
    if (M == "neg") {
        if (Ops.empty()) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        if (!A.Known) { St.WriteOperand(Ops[0], AbsVal::Top()); St.Flags.MakeTop(); return; }
        const unsigned W = Width ? Width : Ops[0].Size;
        const uint64_t R = ((~A.V) + 1ULL) & SizeMaskFor(W);
        St.WriteOperand(Ops[0], AbsVal::Con(R));
        SetSubFlags(St.Flags, 0ULL, A.V, R, W);
        St.Flags.Cf = AbsVal::Con(A.V != 0 ? 1 : 0);
        return;
    }
    if (M == "not") {
        if (Ops.empty()) return;
        const AbsVal A = St.ReadOperand(Ops[0]);
        if (A.Known) St.WriteOperand(Ops[0], AbsVal::Con((~A.V) & (Mask ? Mask : ~0ULL)));
        else St.WriteOperand(Ops[0], AbsVal::Top());
        return;
    }
    if (M == "shl" || M == "sal" || M == "shr" || M == "sar") {
        if (Ops.size() < 2 || Ops[0].Kind != OpKind::Reg) { St.Flags.MakeTop(); return; }
        const AbsVal A = St.ReadOperand(Ops[0]);
        const AbsVal C = St.ReadOperand(Ops[1]);
        const unsigned W = Width ? Width : Ops[0].Size;
        if (!A.Known || !C.Known) {
            St.WriteOperand(Ops[0], AbsVal::Top());
            St.Flags.MakeTop();
            return;
        }
        const unsigned Bits = BitWidthFor(W);
        unsigned cnt = (unsigned)(C.V & (Bits - 1));
        if (cnt == 0) {
            St.WriteOperand(Ops[0], AbsVal::Con(A.V & SizeMaskFor(W)));
            St.Flags.MakeTop();
            return;
        }
        const uint64_t ShiftMask = SizeMaskFor(W);
        uint64_t R = 0;
        AbsVal Cf = AbsVal::Top();
        if (M == "shl" || M == "sal") {
            Cf = AbsVal::Con((A.V >> (Bits - 1)) & 1ULL);
            R = (A.V << cnt) & ShiftMask;
        } else if (M == "shr") {
            Cf = AbsVal::Con((A.V >> (cnt - 1)) & 1ULL);
            R = (A.V >> cnt) & ShiftMask;
        } else {
            const uint64_t Sv = SignExtend(A.V & ShiftMask, W);
            Cf = AbsVal::Con((Sv >> (cnt - 1)) & 1ULL);
            R = (Sv >> cnt) & ShiftMask;
        }
        St.WriteOperand(Ops[0], AbsVal::Con(R));
        St.Flags.Cf = Cf;
        St.Flags.Zf = AbsVal::Con(R == 0 ? 1 : 0);
        St.Flags.Sf = AbsVal::Con((R >> (Bits - 1)) & 1ULL);
        St.Flags.Pf = AbsVal::Con(ParityOf(R));
        St.Flags.Of = AbsVal::Top();
        return;
    }
    if (M == "imul") {
        if (Ops.size() >= 2 && Ops[0].Kind == OpKind::Reg) {
            const AbsVal A = St.ReadOperand(Ops[1]);
            const AbsVal B = (Ops.size() >= 3) ? St.ReadOperand(Ops[2]) : St.ReadOperand(Ops[1]);
            const unsigned W = Width ? Width : Ops[0].Size;
            if (!A.Known || !B.Known) {
                St.WriteOperand(Ops[0], AbsVal::Top());
                St.Flags.MakeTop();
                return;
            }
            const uint64_t sa = SignExtend(A.V & SizeMaskFor(W), W);
            const uint64_t sb = SignExtend(B.V & SizeMaskFor(W), W);
            const uint64_t R = (sa * sb) & SizeMaskFor(W);
            St.WriteOperand(Ops[0], AbsVal::Con(R));
            St.Flags.MakeTop();
        } else {
            SetRegTop(St, 0);
            SetRegTop(St, 2);
            St.Flags.MakeTop();
        }
        return;
    }
    if (M == "mul" || M == "div" || M == "idiv") {
        SetRegTop(St, 0);
        SetRegTop(St, 2);
        St.Flags.MakeTop();
        return;
    }
    if (StartsWith(M, "set") && Ops.size() == 1) {
        const std::string cond = "j" + M.substr(3);
        const int R = EvalCondition(cond, St, nullptr);
        if (R < 0) St.WriteOperand(Ops[0], AbsVal::Top());
        else St.WriteOperand(Ops[0], AbsVal::Con((uint64_t)R));
        return;
    }
    if (StartsWith(M, "cmov") && Ops.size() >= 2) {
        const std::string cond = "j" + M.substr(4);
        const int R = EvalCondition(cond, St, nullptr);
        if (R == 1) St.WriteOperand(Ops[0], St.ReadOperand(Ops[1]));
        else if (R == 0) {  }
        else St.WriteOperand(Ops[0], AbsVal::Top());
        return;
    }
    St.Flags.MakeTop();
    for (int R = 0; R < 16; ++R) SetRegTop(St, R);
}

int EvalCondition(const std::string& M, const State& St, std::string* Why) {
    const Flags& F = St.Flags;
    struct Case { const char* Name; int K; };
    static const Case Table[] = {
        {"jb", 0}, {"jc", 0}, {"jnae", 0}, {"jae", 1}, {"jnb", 1}, {"jnc", 1},
        {"je", 2},  {"jz", 2},   {"jne", 3},  {"jnz", 3},
        {"js", 4},  {"jns", 5},  {"jo", 6},   {"jno", 7},
        {"jp", 8},  {"jpe", 8},  {"jnp", 9},  {"jpo", 9},
        {"jl", 10}, {"jnge", 10},{"jge", 11}, {"jnl", 11},
    };
    int R = -1;
    bool Matched = false;
    for (const Case& C : Table) {
        if (M == C.Name) {
            Matched = true;
            switch (C.K) {
            case 0: R = FlagIs(F.Cf); break;
            case 1: R = FlagIsNot(F.Cf); break;
            case 2: R = FlagIs(F.Zf); break;
            case 3: R = FlagIsNot(F.Zf); break;
            case 4: R = FlagIs(F.Sf); break;
            case 5: R = FlagIsNot(F.Sf); break;
            case 6: R = FlagIs(F.Of); break;
            case 7: R = FlagIsNot(F.Of); break;
            case 8: R = FlagIs(F.Pf); break;
            case 9: R = FlagIsNot(F.Pf); break;
            case 10: R = SfNeOf(F); break;
            case 11: R = SfEqOf(F); break;
            default: break;
            }
            break;
        }
    }
    if (!Matched) {
        if (M == "jbe" || M == "jna") R = TriOr(FlagIs(F.Cf), FlagIs(F.Zf));
        else if (M == "ja" || M == "jnbe") R = TriAnd(FlagIsNot(F.Cf), FlagIsNot(F.Zf));
        else if (M == "jle" || M == "jng") R = TriOr(FlagIs(F.Zf), SfNeOf(F));
        else if (M == "jg" || M == "jnle") R = TriAnd(FlagIsNot(F.Zf), SfEqOf(F));
        else if (M == "jcxz") {
            const AbsVal V = St.Read(RegView(X86_REG_CX));
            if (V.Known) R = (V.V == 0) ? 1 : 0;
        } else if (M == "jecxz") {
            const AbsVal V = St.Read(RegView(X86_REG_ECX));
            if (V.Known) R = (V.V == 0) ? 1 : 0;
        } else if (M == "jrcxz") {
            const AbsVal V = St.Read(RegView(X86_REG_RCX));
            if (V.Known) R = (V.V == 0) ? 1 : 0;
        }
    }
    if (Why) {
        char Buf[160];
        snprintf(Buf, sizeof(Buf), "ZF=%s CF=%s SF=%s OF=%s PF=%s", // I don't know why this is here..
                 F.Zf.Known ? (F.Zf.V ? "1" : "0") : "?",
                 F.Cf.Known ? (F.Cf.V ? "1" : "0") : "?",
                 F.Sf.Known ? (F.Sf.V ? "1" : "0") : "?",
                 F.Of.Known ? (F.Of.V ? "1" : "0") : "?",
                 F.Pf.Known ? (F.Pf.V ? "1" : "0") : "?");
        *Why = Buf;
    }
    return R;
}

}
