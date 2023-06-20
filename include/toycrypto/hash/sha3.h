#pragma once

#ifndef TC_SHA3_H
#define TC_SHA3_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class SHA3_224 final : public HashClass {
	public:
        TC_API SHA3_224();
        TC_API ~SHA3_224() override;

		TC_API void reset() override;
		TC_API void update(const char* buffer, size_t buflen) override;
		TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 28;

    private:
        std::unique_ptr<HashImpl> pimpl;
	};

    class SHA3_256 final : public HashClass {
    public:
        TC_API SHA3_256();
        TC_API ~SHA3_256() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 32;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHA3_384 final : public HashClass {
    public:
        TC_API SHA3_384();
        TC_API ~SHA3_384() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 48;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHA3_512 final : public HashClass {
    public:
        TC_API SHA3_512();
        TC_API ~SHA3_512() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 64;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHAKE128 final : public HashClass {
    public:
        TC_API SHAKE128(unsigned digestbits);
        TC_API ~SHAKE128() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        const size_t digest_size;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHAKE256 final : public HashClass {
    public:
        TC_API SHAKE256(unsigned digestbits);
        TC_API ~SHAKE256() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        const size_t digest_size;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };
}

#endif
