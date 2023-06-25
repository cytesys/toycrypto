#pragma once

#ifndef TC_MD2_H
#define TC_MD2_H

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/hashbase.h>

extern "C++" {

class [[deprecated("MD2 is deprecated. See RFC 6149")]] MD2 final
    : public HBase<uint8_t, true> {
public:
    TC_API MD2();
    TC_API ~MD2() override = default;

    TC_API void finalize() override;

private:
    void reset_subclass() override;
    void process_block() override;

    std::array<uint8_t, 16> m_c{};
    uint8_t m_l{};
};

}

#endif
