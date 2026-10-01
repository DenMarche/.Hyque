#include "ir.hpp"
#include "pe.hpp"
#include "proc.hpp"
#include "regs.hpp"
#include "resolver.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace opr;

namespace {

const char* TargetProcess = "RobloxPlayerBeta.exe";
const char* TargetModule = "RobloxPlayerBeta.dll";
const char* DumpPath = "dumped.bin";
const size_t MaxInsns = 4000000;

bool PickModule(Process& Proc, ModuleInfo& Mod) {
    if (Process::IsInputBinaryADLL(TargetModule)) return Proc.FindModule(TargetModule, Mod);
    return Proc.MainModule(Mod);
}

std::string DescribePredicate(const PredicateResult& R) {
    char Buf[512];
    snprintf(Buf, sizeof(Buf), "0x%08llx %s %s -> %s",
             (unsigned long long)R.BranchRva, R.Mnemonic.c_str(), R.OpStr.c_str(),
             VerdictName(R.Verdict));
    return std::string(Buf);
}

void Resolve(PE& Pe, Disassembler& Dis, const ModuleInfo& Mod, const Section& Sec) {
    const uint32_t VSize = Sec.VirtualSize ? Sec.VirtualSize : Sec.RawSize;
    printf("SEC  % -8s @ 0x%08x\n", Sec.Name.c_str(), Sec.VirtualAddress);
    if (!VSize) return;

    std::vector<uint8_t> Code;
    if (!Pe.ReadRva(Sec.VirtualAddress, VSize, Code)) {
        fprintf(stderr, "Can't read section %s, VSize 0x%x\n", Sec.Name.c_str(), VSize);
        return;
    }

    const uint64_t Base = Mod.Base + Sec.VirtualAddress;
    std::vector<Insn> Insns = Dis.Disassemble(Base, Sec.VirtualAddress, Code.data(), Code.size(), MaxInsns);
    if (MaxInsns && Insns.size() >= MaxInsns) {
        fprintf(stderr, "Capped at %zu, You can raise the cap with MaxInsns! This was done to "
                        "prevent a potential stack overflow. This error is not critical, and you "
                        "can just comment me out.\n", MaxInsns);
    }

    Resolver Res(std::move(Insns), Sec.VirtualAddress, Base);
    std::set<uint32_t> Seen;
    for (const PredicateResult& R : Res.Scan(Dis)) {
        if (Seen.count(R.BranchRva)) continue;
        Seen.insert(R.BranchRva);
        printf("%s\n", DescribePredicate(R).c_str());
        if (R.Verdict == Verdict::AlwaysTaken) {
         //   printf("FALL_THROUGH 0x%llx is dead!\n", (unsigned long long)R.FallThrough);
        } else {
          //  printf("BRANCH to 0x%llx is dead\n", (unsigned long long)R.BranchTarget);
        }
       // printf("UNICORN_FLAGS: %s\n", R.Flags.c_str());
    }
}

int Run() {
    std::string Error;
    Process Proc;
    if (!Proc.Attach(TargetProcess, Error)) {
        fprintf(stderr, "%s\n", Error.c_str());
        return 1;
    }

    ModuleInfo Mod;
    if (!PickModule(Proc, Mod)) {
        fprintf(stderr, "Module is not loaded into PID %u: %s\n", Proc.Pid(), TargetModule);
        for (const ModuleInfo& M : Proc.Modules()) printf("  %s\n", M.Name.c_str());
        return 1;
    }

    uint64_t Unreadable = 0;
    std::vector<uint8_t> Image;
    if (!Proc.ReadImage(Mod, Image, Error, &Unreadable)) {
        fprintf(stderr, "%s\n", Error.c_str());
        return 1;
    }

    std::vector<uint8_t> Rebuilt;
    if (!Process::RebuildPe(Image, Rebuilt, Error)) {
        fprintf(stderr, "Rebuild failed due to exception %s\n", Error.c_str());
        return 1;
    }

    PE Pe;
    if (!Pe.LoadFromMemory(Rebuilt.data(), Rebuilt.size())) {
        fprintf(stderr, "The rebuilt image does not appear as a valid PE\n");
        return 1;
    }
    if (!Process::WriteFile(DumpPath, Rebuilt)) {
        fprintf(stderr, "Can't write %s\n", DumpPath);
        return 1;
    }

    Disassembler Dis;
    if (!Dis.Init(Pe.Is64())) {
        fprintf(stderr, "Capstone initialization failed due to capstone error %d\n", Dis.LastError);
        return 1;
    }

    Section Sec;
    if (!Pe.FindCodeSection(Sec)) {
        fprintf(stderr, "No code section in %s\n", Mod.Name.c_str());
        Dis.Close();
        return 1;
    }

    Resolve(Pe, Dis, Mod, Sec);
    Dis.Close();
    printf("Finished\n");
    return 0;
}

}

int main() {
    try {
        return Run();
    } catch (const std::exception& E) {
        fprintf(stderr, "%s\n", E.what());
        return 1;
    }
}