#include <toycrypto/internal/common.h>
#include <toycrypto/hash/md5.h>

// MD5 initial values
constexpr std::array<uint32_t, 4> MD5_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

// MD5 constants
constexpr std::array<uint32_t, 64> MD5_K = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constexpr std::array<uint8_t, 64> MD5_SIGMA = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

MD5::MD5() : HBase(16) {
    set_digestsize(16);
    reset();
}

void MD5::reset_subclass() {
    m_state.assign(MD5_IV.begin(), MD5_IV.end());
}

void MD5::finalize() {
    pad_md();
    append_length();
}

void MD5::process_block() {
    uint32_t a = m_state[0],
        b = m_state[1],
        c = m_state[2],
        d = m_state[3],
        f, g;
    unsigned i;

    for (i = 0; i < 64; i++) {
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = ((5 * i) + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = ((3 * i) + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        f = f + a + MD5_K[i] + m_block[g];
        a = d;
        d = c;
        c = b;
        b = b + rol(f, MD5_SIGMA[i]);
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;

    clear_block();
}
