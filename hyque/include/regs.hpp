#pragma once
#include <cstdint>

namespace opr {

struct RegisterView {
    int Canonical = -1;
    uint8_t ByteOffset = 0;
    uint8_t ByteSize = 0;
};

RegisterView RegView(unsigned CsRegId);
uint64_t SizeMaskFor(unsigned ByteSize);
uint64_t SignExtend(uint64_t Value, unsigned ByteSize);
unsigned BitWidthFor(unsigned ByteSize);

}