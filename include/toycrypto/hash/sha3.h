#pragma once

#ifndef TC_SHA3_H
#define TC_SHA3_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

class Keccak1600 : public HBase<uint64_t, 25, false> {
public:
    TC_API Keccak1600(size_t rate, size_t digestbitlength, uint8_t dsuf);
    TC_API ~Keccak1600() override;

    TC_API void reset() override;

    TC_API void finalize() override;

private:
    void init_state() override;

    void process_block() override;

    static inline uint64_t m_rc(size_t t);

    static inline size_t lane(size_t x, size_t y);

    const size_t m_capacity;
    const uint8_t m_dsuf;

    std::array<uint64_t, 25> m_v{}; // Working array
};

class SHA3_224 final : public Keccak1600 {
public:
    TC_API SHA3_224() : Keccak1600(448, 224, 0x6) {}
};

class SHA3_256 final : public Keccak1600 {
public:
    TC_API SHA3_256() : Keccak1600(512, 256, 0x6) {}
};

class SHA3_384 final : public Keccak1600 {
public:
    TC_API SHA3_384() : Keccak1600(768, 384, 0x6) {}
};

class SHA3_512 final : public Keccak1600 {
public:
    TC_API SHA3_512() : Keccak1600(1024, 512, 0x6) {}
};

class SHAKE128 final : public Keccak1600 {
public:
    TC_API SHAKE128(size_t digestbitlength) : Keccak1600(256, digestbitlength, 0x1f) {}
};

class SHAKE256 final : public Keccak1600 {
public:
    TC_API SHAKE256(size_t digestbitlength) : Keccak1600(512, digestbitlength, 0x1f) {}
};

}

#endif
