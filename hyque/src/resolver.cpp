#include "resolver.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace opr {
const char* VerdictName(Verdict V) {
    switch (V) {
    case Verdict::AlwaysTaken: return "ALWAYS_TAKEN";
    case Verdict::AlwaysFallThrough: return "ALWAYS_FALLTHROUGH";
    default: return "Unknown";
    }
}

Resolver::Resolver(std::vector<Insn> Insns, uint64_t TextRva, uint64_t TextVa)
    : InsnsValue(std::move(Insns)), TextRvaValue(TextRva), TextVaValue(TextVa) {
    for (AbsVal& S : Seeds) S = AbsVal::Top();
    BuildBlocks();
}

void Resolver::BuildBlocks() {
    BlocksValue.clear();
    RvaToIndex.clear();
    if (InsnsValue.empty()) return;
    for (size_t I = 0; I < InsnsValue.size(); ++I) {
        RvaToIndex[InsnsValue[I].Rva] = I;
    }
    const uint64_t ImageBase = TextVaValue - TextRvaValue;
    std::set<size_t> Leaders;
    Leaders.insert(0);
    for (size_t I = 0; I < InsnsValue.size(); ++I) {
        const Insn& In = InsnsValue[I];
        if (In.IsUnconditionalJump || In.IsRet || In.IsCall) {
            if (I + 1 < InsnsValue.size()) Leaders.insert(I + 1);
        }
        if ((In.IsConditionalJump || In.IsUnconditionalJump) && In.HasTarget) {
            if (In.Target >= ImageBase) {
                const uint32_t TargetRva = (uint32_t)(In.Target - ImageBase);
                std::map<uint32_t, size_t>::const_iterator It = RvaToIndex.find(TargetRva);
                if (It != RvaToIndex.end()) Leaders.insert(It->second);
            }
            if (I + 1 < InsnsValue.size()) Leaders.insert(I + 1);
        }
    }
    std::vector<size_t> Sorted(Leaders.begin(), Leaders.end());
    Sorted.push_back(InsnsValue.size());
    for (size_t K = 0; K + 1 < Sorted.size(); ++K) {
        const size_t First = Sorted[K];
        const size_t Stop = Sorted[K + 1];
        if (First >= Stop) continue;
        BasicBlock Bb;
        Bb.First = First;
        Bb.Last = Stop - 1;
        const Insn& Tail = InsnsValue[Bb.Last];
        if (Tail.IsConditionalJump) {
            Bb.EndsWithCondJump = true;
            Bb.BranchAddr = Tail.Address;
            Bb.BranchTarget = Tail.Target;
            Bb.FallThrough = (Bb.Last + 1 < InsnsValue.size()) ? InsnsValue[Bb.Last + 1].Address : 0;
        }
        BlocksValue.push_back(Bb);
    }
    BlockStartOf.assign(InsnsValue.size(), 0);
    for (const BasicBlock& Bb : BlocksValue) {
        for (size_t I = Bb.First; I <= Bb.Last && I < BlockStartOf.size(); ++I) {
            BlockStartOf[I] = Bb.First;
        }
    }
}

PredicateResult Resolver::Resolve(size_t Index,
                                  const std::vector<Insn>& Insns,
                                  Disassembler& dis) const {
    PredicateResult Res;
    if (Index >= Insns.size() || !Insns[Index].IsConditionalJump) return Res;
    const Insn& Branch = Insns[Index];
    size_t Start = Index;
    if (Index < BlockStartOf.size() && !BlocksValue.empty()) {
        Start = BlockStartOf[Index];
    }
    for (size_t I = Index; I-- > Start;) {
        const Insn& P = Insns[I];
        if (P.IsUnconditionalJump || P.IsRet || P.IsCall) {
            Start = I + 1;
            break;
        }
    }
    State St;
    St.MakeTop();
    for (size_t I = 0; I < Seeds.size(); ++I) {
        if (!Seeds[I].IsTop()) St.Regs[I] = Seeds[I];
    }
    for (size_t I = Start; I < Index; ++I) {
        StepInstruction(Insns[I], St, dis);
        if (St.Flags.AllKnown()) {
            char Buf[128];
            snprintf(Buf, sizeof(Buf), "%s %s", Insns[I].Mnemonic.c_str(),
                     Insns[I].OpStr.c_str());
            Res.Trace.push_back(Buf);
        }
    }
    Res.BranchAddr = Branch.Address;
    Res.BranchRva = Branch.Rva;
    Res.BranchTarget = Branch.Target;
    Res.FallThrough = (Index + 1 < Insns.size()) ? Insns[Index + 1].Address : 0;
    Res.Mnemonic = Branch.Mnemonic;
    Res.OpStr = Branch.OpStr;
    Res.BlockInsns = (uint32_t)(Index - Start);
    Res.ResolvedInsns = (uint32_t)Res.Trace.size();
    std::string Why;
    const int R = EvalCondition(Branch.Mnemonic, St, &Why);
    Res.Flags = Why;
    if (R == 1) Res.Verdict = Verdict::AlwaysTaken;
    else if (R == 0) Res.Verdict = Verdict::AlwaysFallThrough;
    return Res;
}

std::vector<PredicateResult> Resolver::Scan(Disassembler& dis) const {
    std::vector<PredicateResult> Out;
    for (const BasicBlock& Bb : BlocksValue) {
        if (!Bb.EndsWithCondJump) continue;
        PredicateResult R = Resolve(Bb.Last, InsnsValue, dis);
        if (R.Verdict != Verdict::Unknown) Out.push_back(std::move(R));
    }
    return Out;
}

}
