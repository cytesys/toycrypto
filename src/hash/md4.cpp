#include <toycrypto/hash/md4.h>
#include <toycrypto/internal/common.h>

// MD4 initial values
constexpr std::array<uint32_t, 4> MD4_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

MD4::MD4() : HBase(16) {
    set_digestsize(16);
    reset();
}

void MD4::reset_subclass() {
    m_state.assign(MD4_IV.begin(), MD4_IV.end());
}

void MD4::finalize() {
    pad_md();
    append_length();
}

void MD4::md4_ff(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, unsigned x, unsigned s) const {
    a = rol<uint32_t>(a + ((b & c) | ((~b) & d)) + m_block.at(x), s);
}

void MD4::md4_gg(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, unsigned x, unsigned s) const {
    a = rol<uint32_t>(a + ((b & c) | (b & d) | (c & d)) + m_block.at(x) + 0x5a827999u, s);
}

void MD4::md4_hh(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, unsigned x, unsigned s) const {
    a = rol<uint32_t>(a + (b ^ c ^ d) + m_block.at(x) + 0x6ed9eba1u, s);
}

void MD4::process_block() {
    uint32_t a = m_state.at(0),
        b = m_state.at(1),
        c = m_state.at(2),
        d = m_state.at(3);

#if(DEBUG)
    print_block();

#endif
    // Round 1
    md4_ff(a, b, c, d, 0, 3);
    md4_ff(d, a, b, c, 1, 7);
    md4_ff(c, d, a, b, 2, 11);
    md4_ff(b, c, d, a, 3, 19);
    md4_ff(a, b, c, d, 4, 3);
    md4_ff(d, a, b, c, 5, 7);
    md4_ff(c, d, a, b, 6, 11);
    md4_ff(b, c, d, a, 7, 19);
    md4_ff(a, b, c, d, 8, 3);
    md4_ff(d, a, b, c, 9, 7);
    md4_ff(c, d, a, b, 10, 11);
    md4_ff(b, c, d, a, 11, 19);
    md4_ff(a, b, c, d, 12, 3);
    md4_ff(d, a, b, c, 13, 7);
    md4_ff(c, d, a, b, 14, 11);
    md4_ff(b, c, d, a, 15, 19);

    // Round 2
    md4_gg(a, b, c, d, 0, 3);
    md4_gg(d, a, b, c, 4, 5);
    md4_gg(c, d, a, b, 8, 9);
    md4_gg(b, c, d, a, 12, 13);
    md4_gg(a, b, c, d, 1, 3);
    md4_gg(d, a, b, c, 5, 5);
    md4_gg(c, d, a, b, 9, 9);
    md4_gg(b, c, d, a, 13, 13);
    md4_gg(a, b, c, d, 2, 3);
    md4_gg(d, a, b, c, 6, 5);
    md4_gg(c, d, a, b, 10, 9);
    md4_gg(b, c, d, a, 14, 13);
    md4_gg(a, b, c, d, 3, 3);
    md4_gg(d, a, b, c, 7, 5);
    md4_gg(c, d, a, b, 11, 9);
    md4_gg(b, c, d, a, 15, 13);

    // Round 3
    md4_hh(a, b, c, d, 0, 3);
    md4_hh(d, a, b, c, 8, 9);
    md4_hh(c, d, a, b, 4, 11);
    md4_hh(b, c, d, a, 12, 15);
    md4_hh(a, b, c, d, 2, 3);
    md4_hh(d, a, b, c, 10, 9);
    md4_hh(c, d, a, b, 6, 11);
    md4_hh(b, c, d, a, 14, 15);
    md4_hh(a, b, c, d, 1, 3);
    md4_hh(d, a, b, c, 9, 9);
    md4_hh(c, d, a, b, 5, 11);
    md4_hh(b, c, d, a, 13, 15);
    md4_hh(a, b, c, d, 3, 3);
    md4_hh(d, a, b, c, 11, 9);
    md4_hh(c, d, a, b, 7, 11);
    md4_hh(b, c, d, a, 15, 15);

    m_state.at(0) += a;
    m_state.at(1) += b;
    m_state.at(2) += c;
    m_state.at(3) += d;

    clear_block();
}
