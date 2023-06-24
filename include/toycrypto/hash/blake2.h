#pragma once

#ifndef TC_BLAKE2_H
#define TC_BLAKE2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<x32or64 T>
class _Blake2Impl : public HBase<T, 16, false> {
public:
    TC_API _Blake2Impl();
    TC_API ~_Blake2Impl() override;

    TC_API void finalize() override;

protected:
    void print_v();

private:
    void process_block() override;
    void init_state() override;
    inline void blake2_g(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

    std::array<T, 16> m_v{}; // Working array

    std::vector<T> m_key{};

    static const unsigned m_rounds;
    static const std::array<T, 8> &m_k;
    static const std::array<unsigned, 4> m_rc;
};

class BLAKE2s final : public _Blake2Impl<uint32_t> {
public:
    TC_API BLAKE2s(unsigned digestbits);
};

class BLAKE2b final : public _Blake2Impl<uint64_t> {
public:
    TC_API BLAKE2b(unsigned digestbits);
};

}

#endif
