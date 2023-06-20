#pragma once

#ifndef TC_BLAKE2_H
#define TC_BLAKE2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class BLAKE2S_224 final : public HashClass {
    public:
        TC_API BLAKE2S_224();
        TC_API ~BLAKE2S_224() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 28;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class BLAKE2S_256 final : public HashClass {
    public:
        TC_API BLAKE2S_256();
        TC_API ~BLAKE2S_256() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 32;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class BLAKE2B_384 final : public HashClass {
    public:
        TC_API BLAKE2B_384();
        TC_API ~BLAKE2B_384() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 48;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class BLAKE2B_512 final : public HashClass {
    public:
        TC_API BLAKE2B_512();
        TC_API ~BLAKE2B_512() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 64;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };
}

#endif
