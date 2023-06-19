#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/sha1.h>

#define SHA1_ROL(a, n) ROL((a), (n), 32)
#define SHA1_ROR(a, n) ROR((a), (n), 32)

class SHA1Impl final : public HashImpl {
public:
    SHA1Impl();

    ~SHA1Impl() override = default;

    void reset() override;

    void update(const char *buffer, size_t buflen) override;

    void finalize() override;

    void digest(unsigned char *output, size_t outlen) override;

    void hexdigest(char *output, size_t outlen) override;

private:
    void m_process_block();

    static const std::array<uint32_t, 5> m_iv;
    static const std::array<uint32_t, 4> m_k;

    std::array<uint32_t, 5> m_h{};
    std::array<uint32_t, 80> m_words{};
    size_t m_length{};
    unsigned m_index{};
    HashState m_state{};
};

// SHA1 initial values
const std::array<uint32_t, 5> SHA1Impl::m_iv = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

// SHA1 constants
const std::array<uint32_t, 4> SHA1Impl::m_k = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

void SHA1Impl::reset() {
    m_words.fill(0);
    m_h = m_iv;
    m_length = 0;
    m_index = 0;
    m_state = HASH_INIT;
}

SHA1Impl::SHA1Impl() { reset(); }

void SHA1Impl::update(const char *const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_length += buflen * 8;
    m_state = HASH_UPDATE;

    while (offset < buflen) {
        m_words.at(m_index / 4) ^= SHA1_ROR((uint32_t)buffer[offset], ((m_index + 1) % 4) * 8);

        offset++;
        if (++m_index % 64 == 0) {
            m_process_block();
            m_index = 0;
        }
    }
}

void SHA1Impl::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append a padding bit
    m_words.at(m_index / 4) ^= SHA1_ROR(0x80ul, ((m_index + 1) % 4) * 8);

    // Process the block if the message length don't fit
    if ((8ull + m_index) >= 64)
        m_process_block();

    // Append the message length
    m_words.at(14) = (m_length >> 32) & 0xffffffff;
    m_words.at(15) = m_length & 0xffffffff;

    m_state = HASH_FINAL;
    m_process_block();
}

void SHA1Impl::digest(unsigned char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < 20)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < 20; i++)
        *(output + i) = SHA1_ROL(m_h.at(i / 4), ((i + 1) % 4) * 8) & 0xff;
}

void SHA1Impl::hexdigest(char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (outlen < 41)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < 5; i++)
        snprintf(output + (8ull * i), 9, "%08x", m_h.at(i));
}

void SHA1Impl::m_process_block() {
    uint32_t a = m_h.at(0),
        b = m_h.at(1),
        c = m_h.at(2),
        d = m_h.at(3),
        e = m_h.at(4),
        f, k, tmp;

    unsigned i;

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_block __\n");
    for (i = 0; i < 16; i++) {
        fprintf(stderr, "%08x ", m_words.at(i));
        if ((i + 1) % 4 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    for (i = 16; i < 80; i++) {
        m_words.at(i) = SHA1_ROL(
            m_words.at((-3ll) + i) ^ \
            m_words.at((-8ll) + i) ^ \
            m_words.at((-14ll) + i) ^ \
            m_words.at((-16ll) + i),
            1
        );
    }

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = m_k.at(0);
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = m_k.at(1);
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = m_k.at(2);
        } else {
            f = b ^ c ^ d;
            k = m_k.at(3);
        }

        tmp = SHA1_ROL(a, 5) + f + e + k + m_words.at(i);
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = tmp;
    }

    m_h.at(0) += a;
    m_h.at(1) += b;
    m_h.at(2) += c;
    m_h.at(3) += d;
    m_h.at(4) += e;

    m_words.fill(0);
}

SHA1::SHA1() : pimpl(new SHA1Impl()) {}

SHA1::~SHA1() = default;

void SHA1::reset() { pimpl->reset(); }

void SHA1::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA1::finalize() { pimpl->finalize(); }

void SHA1::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA1::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}
