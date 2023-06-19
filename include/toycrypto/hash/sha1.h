#pragma once

#ifndef TC_SHA1_H
#define TC_SHA1_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/hash/hash_common.h>

extern "C++" {
    class [[deprecated("SHA1 is deprecated. See FIPS 180-5")]] SHA1 final : public HashClass {
	public:
		TC_API SHA1();
		TC_API ~SHA1() override;

		TC_API void reset() override;
		TC_API void update(const char* buffer, size_t buflen) override;
		TC_API void finalize() override;
        TC_API void digest(unsigned char* output, size_t outlen) override;
        TC_API void hexdigest(char* output, size_t outlen) override;

		TC_API static const size_t digest_size = 20;

	private:
        std::unique_ptr<HashImpl> pimpl;
	};
}

#endif
