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


//    class BLAKE2S_224 final : public HashClass {
//    public:
//        TC_API BLAKE2S_224();
//        TC_API ~BLAKE2S_224() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 28;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };

//    class BLAKE2S_256 final : public HashClass {
//    public:
//        TC_API BLAKE2S_256();
//        TC_API ~BLAKE2S_256() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 32;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };

//    class BLAKE2B_384 final : public HashClass {
//    public:
//        TC_API BLAKE2B_384();
//        TC_API ~BLAKE2B_384() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 48;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };

//    class BLAKE2B_512 final : public HashClass {
//    public:
//        TC_API BLAKE2B_512();
//        TC_API ~BLAKE2B_512() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 64;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };
}

#endif
