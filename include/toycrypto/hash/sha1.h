#pragma once

#ifndef TC_SHA1_H
#define TC_SHA1_H

#include <string>
#include <array>

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

class [[deprecated("SHA1 is deprecated. See FIPS 180-5")]] SHA1 final
    : public HBase<uint32_t, 16, true> {
public:
    TC_API SHA1();
    TC_API ~SHA1 () override;

    TC_API void finalize() override;

protected:
    TC_API void init_state() override;
    TC_API void process_block() override;

    std::array<uint32_t, 80> m_words{};
};

}

#endif
