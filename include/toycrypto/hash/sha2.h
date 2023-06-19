#pragma once

#ifndef TC_SHA2_H
#define TC_SHA2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class SHA224 final : public HashClass {
	public:
		TC_API SHA224();
		TC_API ~SHA224() override;

		TC_API void reset() override;
		TC_API void update(const char* buffer, size_t buflen) override;
		TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API void hexdigest(char* output, size_t outlen) override;

		TC_API static const size_t digest_size = 28;

	private:
        std::unique_ptr<HashImpl> pimpl;
	};

    class SHA256 final : public HashClass {
    public:
        TC_API SHA256();
        TC_API ~SHA256() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API void hexdigest(char* output, size_t outlen) override;

        TC_API static const size_t digest_size = 32;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHA384 final : public HashClass {
    public:
        TC_API SHA384();
        TC_API ~SHA384() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API void hexdigest(char* output, size_t outlen) override;

        TC_API static const size_t digest_size = 48;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class SHA512 final : public HashClass {
    public:
        TC_API SHA512();
        TC_API ~SHA512() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API void hexdigest(char* output, size_t outlen) override;

        TC_API static const size_t digest_size = 64;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };
}

#endif
