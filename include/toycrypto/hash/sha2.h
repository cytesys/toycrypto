#pragma once

#ifndef TC_SHA2_H
#define TC_SHA2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<UTYPE T>
class Sha2Impl : public HBase<T, true> {
public:
    TC_API Sha2Impl();

    TC_API void finalize() final;

protected:
    void reset_subclass() override;

private:
    void process_block() final;

    static const std::vector<T> m_k;
    static const std::vector<unsigned> m_rc;
};

class SHA224 final : public Sha2Impl<uint32_t> {
public:
    TC_API SHA224();

    TC_API ~SHA224() override = default;

private:
    void reset_subclass() override;
};

class SHA256 final : public Sha2Impl<uint32_t> {
public:
    TC_API SHA256();

    TC_API ~SHA256() override = default;

private:
    void reset_subclass() override;
};

class SHA384 final : public Sha2Impl<uint64_t> {
public:
    TC_API SHA384();

    TC_API ~SHA384() override = default;

private:
    void reset_subclass() override;
};

class SHA512 final : public Sha2Impl<uint64_t> {
public:
    TC_API SHA512();

    TC_API ~SHA512() override = default;

private:
    void reset_subclass() override;
};

}

#endif
