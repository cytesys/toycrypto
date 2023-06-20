#pragma once

#ifndef TC_MD4_H
#define TC_MD4_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class [[deprecated("MD4 is deprecated. See RFC 6150")]] MD4 final : public HashClass {
	public:
		TC_API MD4();
        TC_API ~MD4() override;

        TC_API void reset() override;
        TC_API void update(const char* const buffer, const size_t buflen) override;
        TC_API void finalize() override;
        TC_API void digest(unsigned char* const output, const size_t outlen) override;
        TC_API std::string hexdigest() override;

		TC_API static const size_t digest_size = 16;

    private:
        std::unique_ptr<HashImpl> pimpl;
	};
}

#endif
