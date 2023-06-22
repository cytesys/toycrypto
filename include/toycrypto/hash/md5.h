#pragma once

#ifndef TC_MD5_H
#define TC_MD5_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {
    class [[deprecated("MD5 is deprecated. See RFC 6151")]] MD5 final
        : public HBase<uint32_t, 16, false> {
	public:
		TC_API MD5();
        TC_API ~MD5() override;

        TC_API void finalize() override;

    private:
        void init_state() override;
        void process_block() override;
	};
}

#endif
