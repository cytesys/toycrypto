#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/md4.h>
#include <toycrypto/common/util.h>

#define MD4_ROR(a, n) ROR((a), (n), 32)
#define MD4_ROL(a, n) ROL((a), (n), 32)

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define FF(a, b, c, d, x, s) (a) = (MD4_ROL((a) + F((b), (c), (d)) + this->m_block.at(x), (s)))
#define GG(a, b, c, d, x, s) (a) = (MD4_ROL((a) + G((b), (c), (d)) + this->m_block.at(x) + 0x5a827999ul, (s)))
#define HH(a, b, c, d, x, s) (a) = (MD4_ROL((a) + H((b), (c), (d)) + this->m_block.at(x) + 0x6ed9eba1ul, (s)))

class MD4Impl final : public HashImpl {
public:
    MD4Impl();
    ~MD4Impl() override = default;

    void reset() override;
    void update(const char* const buffer, const size_t buflen) override;
    void finalize() override;
    void digest(unsigned char* const output, const size_t outlen) override;

private:
	void m_process_block();

	static const std::array<uint32_t, 4> m_iv;

    std::array<uint32_t, 16> m_block{};
    std::array<uint32_t, 4> m_h{};
    unsigned m_index{};
    size_t m_length{};
    HashState m_state{};
};

const std::array<uint32_t, 4> MD4Impl::m_iv = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

MD4Impl::MD4Impl() {
    reset();
}

void MD4Impl::reset() {
    m_block.fill(0);
    m_h = m_iv;
    m_index = 0;
    m_length = 0;
    m_state = HASH_INIT;
}

void MD4Impl::update(const char* const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_length += buflen * 8;
    m_state = HASH_UPDATE;

	while (offset < buflen) {
        m_block.at(m_index / 4) ^= MD4_ROL((uint32_t)buffer[offset], (m_index % 4) * 8);
		offset++;
        if ((++m_index % 64) == 0) {
            m_process_block();
            m_index = 0;
		}
	}
}

void MD4Impl::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append a padding bit
    m_block.at(m_index / 4) ^= MD4_ROL(0x80ul, (m_index % 4) * 8);

	// Process the block if the message length don't fit
    if ((8ull + m_index) >= 64)
        m_process_block();

	// Append the message length
    m_block.at(14) = m_length & 0xffffffff;
    m_block.at(15) = (m_length >> 32) & 0xffffffff;

    m_state = HASH_FINAL;
    m_process_block();
}

void MD4Impl::digest(unsigned char* const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < 16)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < 16; i++)
        *(output + i) = MD4_ROR(m_h.at(i / 4), (i % 4) * 8) & 0xff;
}


void MD4Impl::m_process_block() {
    uint32_t a = m_h.at(0),
        b = m_h.at(1),
        c = m_h.at(2),
        d = m_h.at(3);

#if(DEBUG)
    // Debug
    for (unsigned i = 0; i < m_block.size(); i++) {
        fprintf(stderr, "%.08x ", m_block.at(i));
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

    m_h.at(0) += a;
    m_h.at(1) += b;
    m_h.at(2) += c;
    m_h.at(3) += d;

    m_block.fill(0);
}

MD4::MD4() : pimpl(new MD4Impl) {}

MD4::~MD4() {}

void MD4::reset() { pimpl->reset(); }

void MD4::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void MD4::finalize() { pimpl->finalize(); }

void MD4::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

std::string MD4::hexdigest() {
    unsigned char buffer[digest_size];
    pimpl->digest(buffer, digest_size);
    return TC::hexdigest(buffer, digest_size);
}
