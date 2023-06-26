#pragma once

#ifndef TC_BLAKE2_H
#define TC_BLAKE2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<UTYPE T>
class Blake2Impl : public HBase<T, false> {
public:
    TC_API Blake2Impl();

    TC_API void finalize() final;

    [[maybe_unused]] TC_API void set_key(const char* keybuf, size_t keybuflen);

private:
    void process_block() final;

    void reset_subclass() final;

    inline void blake2_g(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

    static const unsigned m_rounds;
    static const std::array<T, 8> &m_k;
    static const std::vector<unsigned> m_rc;
};

class BLAKE2s final : public Blake2Impl<uint32_t> {
public:
    TC_API explicit BLAKE2s(unsigned digestbits);
    TC_API ~BLAKE2s() final = default;
};

class BLAKE2b final : public Blake2Impl<uint64_t> {
public:
    TC_API explicit BLAKE2b(unsigned digestbits);
    TC_API ~BLAKE2b() final = default;
};

}

#endif
