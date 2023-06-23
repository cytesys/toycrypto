#pragma once

#ifndef TC_BLAKE_H
#define TC_BLAKE_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<x32or64 T>
class _BlakeImpl : public HBase<T, 16, true> {
public:
    TC_API _BlakeImpl() { throw std::invalid_argument("Blake was instanciated with a wrong type"); }
    TC_API ~_BlakeImpl() override = default;

    TC_API void finalize() override;
    TC_API void set_salt(const char* buffer, size_t buflen);

protected:
    void init_intermediate();
    void print_m_v() {
        fprintf(stderr, "__ m_v __\n");
        for (int i = 0; i < m_v.size(); i++) {
            fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) * 2), (uint64_t)(m_v.at(i)));
            if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }

private:
    void process_block() override;
    inline void blake_g(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

    std::array<T, 16> m_v{}; // Working array
    std::array<T, 4> m_salt{};

    static const unsigned m_rounds;
    static const std::array<T, 16> m_k;
    static const std::array<unsigned, 4> m_rc;
};

class BLAKE224 final : public _BlakeImpl<uint32_t>
{
public:
    TC_API BLAKE224();

private:
    void init_state() override;
};

class BLAKE256 final : public _BlakeImpl<uint32_t>
{
public:
    TC_API BLAKE256();

private:
    void init_state() override;
};

class BLAKE384 final : public _BlakeImpl<uint64_t>
{
public:
    TC_API BLAKE384();

private:
    void init_state() override;
};

class BLAKE512 final : public _BlakeImpl<uint64_t>
{
public:
    TC_API BLAKE512();

private:
    void init_state() override;
};
}

#endif
