#include <toycrypto/internal/common.h>
#include <toycrypto/hash/sha1.h>

#define SHA1_ROL(a, n) ROL((a), (n), 32)
#define SHA1_ROR(a, n) ROR((a), (n), 32)

// SHA1 initial values
constexpr std::array<uint32_t, 5> SHA1_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

// SHA1 constants
constexpr std::array<uint32_t, 4> SHA1_K = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

void SHA1::init_state() {
    m_state.assign(5, 0);
    std::copy(SHA1_IV.begin(), SHA1_IV.end(), m_state.begin());
}

SHA1::SHA1() {
    set_digestsize(20);
    reset();
}

SHA1::~SHA1() = default;

void SHA1::finalize() {
    pad_md();
    append_length();
}

void SHA1::process_block() {
    uint32_t a = m_state.at(0),
        b = m_state.at(1),
        c = m_state.at(2),
        d = m_state.at(3),
        e = m_state.at(4),
        f, k, tmp;

    unsigned i;

#if(DEBUG)
    print_m_block();

#endif
    for (i = 0; i < 80; i++) {
        if (i < 16) {
            m_words.at(i) = m_block.at(i);
        } else {
            m_words.at(i) = SHA1_ROL(
                m_words.at((-3ll) + i) ^ \
                                         m_words.at((-8ll) + i) ^ \
                      m_words.at((-14ll) + i) ^ \
                      m_words.at((-16ll) + i),
                1
                );
        }
    }

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K.at(0);
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K.at(1);
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K.at(2);
        } else {
            f = b ^ c ^ d;
            k = SHA1_K.at(3);
        }

        tmp = SHA1_ROL(a, 5) + f + e + k + m_words.at(i);
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = tmp;
    }

    m_state.at(0) += a;
    m_state.at(1) += b;
    m_state.at(2) += c;
    m_state.at(3) += d;
    m_state.at(4) += e;

    m_words.fill(0);
    clear_m_block();
}
