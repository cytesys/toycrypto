#include <toycrypto/hash/md4.h>
#include <toycrypto/internal/common.h>

#define MD4_ROR(a, n) ROR((a), (n), 32)
#define MD4_ROL(a, n) ROL((a), (n), 32)

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define FF(a, b, c, d, x, s) (a) = (MD4_ROL((a) + F((b), (c), (d)) + m_block.at(x), (s)))
#define GG(a, b, c, d, x, s) (a) = (MD4_ROL((a) + G((b), (c), (d)) + m_block.at(x) + 0x5a827999ul, (s)))
#define HH(a, b, c, d, x, s) (a) = (MD4_ROL((a) + H((b), (c), (d)) + m_block.at(x) + 0x6ed9eba1ul, (s)))

// MD4 initial values
constexpr std::array<uint32_t, 4> MD4_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

MD4::MD4() {
    set_digestsize(16);
    reset();
}

MD4::~MD4() = default;

void MD4::init_state() {
    m_state.assign(MD4_IV.begin(), MD4_IV.end());
}

void MD4::finalize() {
    pad_md();
    append_length();
}

void MD4::process_block() {
    uint32_t a = m_state.at(0),
        b = m_state.at(1),
        c = m_state.at(2),
        d = m_state.at(3);

#if(DEBUG)
    // Debug
    for (unsigned i = 0; i < m_block.size(); i++) {
        fprintf(stderr, "%08x ", m_block.at(i));
        if ((i + 1) % 4 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    // Round 1
    FF(a, b, c, d, 0, 3);
    FF(d, a, b, c, 1, 7);
    FF(c, d, a, b, 2, 11);
    FF(b, c, d, a, 3, 19);
    FF(a, b, c, d, 4, 3);
    FF(d, a, b, c, 5, 7);
    FF(c, d, a, b, 6, 11);
    FF(b, c, d, a, 7, 19);
    FF(a, b, c, d, 8, 3);
    FF(d, a, b, c, 9, 7);
    FF(c, d, a, b, 10, 11);
    FF(b, c, d, a, 11, 19);
    FF(a, b, c, d, 12, 3);
    FF(d, a, b, c, 13, 7);
    FF(c, d, a, b, 14, 11);
    FF(b, c, d, a, 15, 19);

    // Round 2
    GG(a, b, c, d, 0, 3);
    GG(d, a, b, c, 4, 5);
    GG(c, d, a, b, 8, 9);
    GG(b, c, d, a, 12, 13);
    GG(a, b, c, d, 1, 3);
    GG(d, a, b, c, 5, 5);
    GG(c, d, a, b, 9, 9);
    GG(b, c, d, a, 13, 13);
    GG(a, b, c, d, 2, 3);
    GG(d, a, b, c, 6, 5);
    GG(c, d, a, b, 10, 9);
    GG(b, c, d, a, 14, 13);
    GG(a, b, c, d, 3, 3);
    GG(d, a, b, c, 7, 5);
    GG(c, d, a, b, 11, 9);
    GG(b, c, d, a, 15, 13);

    // Round 3
    HH(a, b, c, d, 0, 3);
    HH(d, a, b, c, 8, 9);
    HH(c, d, a, b, 4, 11);
    HH(b, c, d, a, 12, 15);
    HH(a, b, c, d, 2, 3);
    HH(d, a, b, c, 10, 9);
    HH(c, d, a, b, 6, 11);
    HH(b, c, d, a, 14, 15);
    HH(a, b, c, d, 1, 3);
    HH(d, a, b, c, 9, 9);
    HH(c, d, a, b, 5, 11);
    HH(b, c, d, a, 13, 15);
    HH(a, b, c, d, 3, 3);
    HH(d, a, b, c, 11, 9);
    HH(c, d, a, b, 7, 11);
    HH(b, c, d, a, 15, 15);

    m_state.at(0) += a;
    m_state.at(1) += b;
    m_state.at(2) += c;
    m_state.at(3) += d;

    m_block.assign(m_block.size(), 0);
}
