#pragma once
#include "ir.hpp"
#include "state.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace opr {
enum class Verdict {
    Unknown,
    AlwaysTaken,
    AlwaysFallThrough,
};

const char* VerdictName(Verdict V);
struct BasicBlock {
    size_t First = 0;
    size_t Last = 0;
    bool EndsWithCondJump = false;
    uint64_t BranchAddr = 0;
    uint64_t BranchTarget = 0;
    uint64_t FallThrough = 0;
};

struct PredicateResult {
    Verdict Verdict = Verdict::Unknown;
    uint64_t BranchAddr = 0;
    uint32_t BranchRva = 0;
    uint64_t BranchTarget = 0;
    uint64_t FallThrough = 0;
    std::string Mnemonic;
    std::string OpStr;
    std::string Flags;
    uint32_t BlockInsns = 0;
    uint32_t ResolvedInsns = 0;
    std::vector<std::string> Trace;
};

class Resolver {
public:
    Resolver(std::vector<Insn> Insns, uint64_t TextRva, uint64_t TextVa);
    const std::vector<Insn>& Instructions() const { return InsnsValue; }
    const std::vector<BasicBlock>& Blocks() const { return BlocksValue; }
    PredicateResult Resolve(size_t Index, const std::vector<Insn>& Insns,
                            Disassembler& dis) const;
    std::vector<PredicateResult> Scan(Disassembler& dis) const;
    void SetSeed(int canonicalReg, uint64_t value) { Seeds[canonicalReg] = AbsVal::Con(value); }
    void ClearSeeds() { for (AbsVal& S : Seeds) S = AbsVal::Top(); }
private:
    void BuildBlocks();
    std::vector<Insn> InsnsValue;
    uint64_t TextRvaValue = 0;
    uint64_t TextVaValue = 0;
    std::vector<BasicBlock> BlocksValue;
    std::map<uint32_t, size_t> RvaToIndex;
    std::vector<size_t> BlockStartOf;
    std::array<AbsVal, 16> Seeds{};
};
}
