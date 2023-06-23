#pragma once

#ifndef TC_MD4_H
#define TC_MD4_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {
    class [[deprecated("MD4 is deprecated. See RFC 6150")]] MD4 final
        : public HBase<uint32_t, 16, false> {
	public:
		TC_API MD4();
        TC_API ~MD4() override;

        TC_API void finalize() override;

    private:
        void init_state() override;
        void process_block() override;

        inline void md4_ff(uint32_t&, uint32_t, uint32_t, uint32_t, unsigned, unsigned) const;
        inline void md4_gg(uint32_t&, uint32_t, uint32_t, uint32_t, unsigned, unsigned) const;
        inline void md4_hh(uint32_t&, uint32_t, uint32_t, uint32_t, unsigned, unsigned) const;
	};
}

#endif
