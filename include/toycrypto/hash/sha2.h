#pragma once

#ifndef TC_SHA2_H
#define TC_SHA2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

template<x32or64 T>
class _Sha2Impl : public HBase<T, 16, true> {
public:
    TC_API _Sha2Impl();
    TC_API ~_Sha2Impl() override;

    TC_API void finalize() override;

protected:
    void init_intermediate();

private:
    void process_block() override;

    std::vector<T> m_v{}; // Working array

    static const std::vector<T> m_k;
    static const std::array<unsigned, 12> m_rc;
};

class SHA224 final : public _Sha2Impl<uint32_t> {
public:
    TC_API SHA224();

private:
    void init_state() override;
};

class SHA256 final : public _Sha2Impl<uint32_t> {
public:
    TC_API SHA256();

private:
    void init_state() override;
};

class SHA384 final : public _Sha2Impl<uint64_t> {
public:
    TC_API SHA384();

private:
    void init_state() override;
};

class SHA512 final : public _Sha2Impl<uint64_t> {
public:
    TC_API SHA512();

private:
    void init_state() override;
};

//    class SHA224 final : public HashClass {
//	public:
//		TC_API SHA224();
//		TC_API ~SHA224() override;

//		TC_API void reset() override;
//		TC_API void update(const char* buffer, size_t buflen) override;
//		TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//		TC_API static const size_t digest_size = 28;

//	private:
//        std::unique_ptr<HashImpl> pimpl;
//	};

//    class SHA256 final : public HashClass {
//    public:
//        TC_API SHA256();
//        TC_API ~SHA256() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 32;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };

//    class SHA384 final : public HashClass {
//    public:
//        TC_API SHA384();
//        TC_API ~SHA384() override;

//        TC_API void reset() override;
//        TC_API void update(const char* buffer, size_t buflen) override;
//        TC_API void finalize() override;
//        TC_API void digest(unsigned char* output, size_t outlen) override;
//        TC_API std::string hexdigest() override;

//        TC_API static const size_t digest_size = 48;

//    private:
//        std::unique_ptr<HashImpl> pimpl;
//    };

//    class SHA512 final : public HashClass {
//    public:
//        TC_API SHA512();
//        TC_API ~SHA512() override;

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
