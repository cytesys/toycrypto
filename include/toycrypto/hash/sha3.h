#pragma once

#ifndef TC_SHA3_H
#define TC_SHA3_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

class Keccak1600 : public HBase<uint64_t, false> {
public:
    TC_API Keccak1600(size_t rate, uint8_t dsuf, size_t digestsize = 0);

    TC_API void finalize() final;

private:
    void reset_subclass() final;

    void process_block() final;

    static inline uint64_t m_rc(size_t t);

    static inline size_t lane(size_t x, size_t y);

    const size_t m_capacity;
    const uint8_t m_dsuf;
};

class SHA3_224 final : public Keccak1600 {
public:
    TC_API SHA3_224() : Keccak1600(56, 0x6, 28) { reset(); }
    TC_API ~SHA3_224() override = default;
};

class SHA3_256 final : public Keccak1600 {
public:
    TC_API SHA3_256() : Keccak1600(64, 0x6, 32) { reset(); }
    TC_API ~SHA3_256() override = default;
};

class SHA3_384 final : public Keccak1600 {
public:
    TC_API SHA3_384() : Keccak1600(96, 0x6, 48) { reset(); }
    TC_API ~SHA3_384() override = default;
};

class SHA3_512 final : public Keccak1600 {
public:
    TC_API SHA3_512() : Keccak1600(128, 0x6, 64) { reset(); }
    TC_API ~SHA3_512() override = default;
};

class SHAKE128 final : public Keccak1600 {
public:
    TC_API SHAKE128() : Keccak1600(32, 0x1f) { reset(); }
    TC_API ~SHAKE128() override = default;
};

class SHAKE256 final : public Keccak1600 {
public:
    TC_API SHAKE256() : Keccak1600(64, 0x1f) { reset(); }
    TC_API ~SHAKE256() override = default;
};

}

#endif
