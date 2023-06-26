#pragma once

#ifndef TC_BLAKE_H
#define TC_BLAKE_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<UTYPE T>
class BlakeImpl : public HBase<T, true> {
public:
    TC_API BlakeImpl();

    TC_API void finalize() final;

    [[maybe_unused]] TC_API void set_salt(const char* buffer, size_t buflen);

protected:
    void reset_subclass() override;

private:
    void process_block() final;

    inline void blake_g(unsigned, unsigned, unsigned, unsigned, unsigned, unsigned);

    std::vector<T> m_salt{};

    static const unsigned m_rounds;
    static const std::vector<T> m_k;
    static const std::vector<unsigned> m_rc;
};

class BLAKE224 final : public BlakeImpl<uint32_t>
{
public:
    TC_API BLAKE224();
    TC_API ~BLAKE224() final = default;

private:
    void reset_subclass() override;
};

class BLAKE256 final : public BlakeImpl<uint32_t>
{
public:
    TC_API BLAKE256();
    TC_API ~BLAKE256() final = default;

private:
    void reset_subclass() override;
};

class BLAKE384 final : public BlakeImpl<uint64_t>
{
public:
    TC_API BLAKE384();
    TC_API ~BLAKE384() final = default;

private:
    void reset_subclass() override;
};

class BLAKE512 final : public BlakeImpl<uint64_t>
{
public:
    TC_API BLAKE512();
    TC_API ~BLAKE512() final = default;

private:
    void reset_subclass() override;
};

}

#endif
