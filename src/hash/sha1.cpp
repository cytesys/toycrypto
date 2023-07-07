#include <toycrypto/internal/common.h>
#include <toycrypto/hash/sha1.h>

// SHA1 initial values
constexpr std::array<uint32_t, 5> SHA1_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

// SHA1 constants
constexpr std::array<uint32_t, 4> SHA1_K = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

SHA1::SHA1() : HBase(16) {
    set_digestsize(20);
    reset();
}

void SHA1::reset_subclass() {
    m_tmp.assign(80, 0);
    m_state.assign(SHA1_IV.begin(), SHA1_IV.end());
}

void SHA1::finalize() {
    pad_md();
    append_length();
}

void SHA1::process_block() {
    uint32_t a = m_state[0],
        b = m_state[1],
        c = m_state[2],
        d = m_state[3],
        e = m_state[4],
        f, k, tmp;

    unsigned i;

    for (i = 0; i < 80; i++) {
        if (i < 16) {
            m_tmp[i] = m_block[i];
        } else {
            m_tmp[i] = rol(
                m_tmp[(-3ll) + i] ^ m_tmp[(-8ll) + i] ^
                m_tmp[(-14ll) + i] ^ m_tmp[(-16ll) + i],
                1
            );
        }
    }

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K[2];
        } else {
            f = b ^ c ^ d;
            k = SHA1_K[3];
        }

        tmp = rol(a, 5) + f + e + k + m_tmp[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = tmp;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;

    clear_block();
}
