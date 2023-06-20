#pragma once

#ifndef TC_BLAKE_H
#define TC_BLAKE_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class BLAKE224 final : public HashClass {
	public:
		TC_API BLAKE224();
		TC_API ~BLAKE224() override;

		TC_API void reset() override;
		TC_API void update(const char* buffer, size_t buflen) override;
		TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

		TC_API static const size_t digest_size = 28;

    private:
        std::unique_ptr<HashImpl> pimpl;
	};

    class BLAKE256 final : public HashClass {
    public:
        TC_API BLAKE256();
        TC_API ~BLAKE256() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 32;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class BLAKE384 final : public HashClass {
    public:
        TC_API BLAKE384();
        TC_API ~BLAKE384() override;

        TC_API void reset() override;
        TC_API void update(const char* buffer, size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API std::string hexdigest() override;

        TC_API static const size_t digest_size = 48;

    private:
        std::unique_ptr<HashImpl> pimpl;
    };

    class BLAKE512 final : public HashClass {
    public:
        TC_API BLAKE512();
        TC_API ~BLAKE512() override;

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
