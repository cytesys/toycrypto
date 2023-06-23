#pragma once

#ifndef TC_BLAKE_H
#define TC_BLAKE_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<x32or64 T>
class _BlakeImpl : public HBase<T, 16, true> {
public:
    TC_API _BlakeImpl();
    TC_API ~_BlakeImpl() override;

    TC_API void finalize() override;
    [[maybe_unused]] TC_API void set_salt(const char* buffer, size_t buflen);

protected:
    void init_intermediate();
    void print_v();

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
