#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/md5.h>

#define MD5_ROL(a, n) ROL((a), (n), 32)
#define MD5_ROR(a, n) ROR((a), (n), 32)

class MD5Impl final : public HashImpl {
public:
    MD5Impl();
    ~MD5Impl() override = default;

    void reset() override;
    void update(const char* const buffer, const size_t buflen) override;
    void finalize() override;
    void digest(unsigned char* const output, const size_t outlen) override;
    void hexdigest(char* const output, const size_t outlen) override;

private:
	void m_process_block();

	static const std::array<uint32_t, 64> m_k;
	static const std::array<uint8_t, 64> m_s;
    static const std::array<uint32_t, 4> m_iv;

    std::array<uint32_t, 16> m_block{};
    std::array<uint32_t, 4> m_h{};
    size_t m_length{};
    unsigned m_index{};
    HashState m_state{};
};

// MD5 constants
const std::array<uint32_t, 64> MD5Impl::m_k = {
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

const std::array<uint8_t, 64> MD5Impl::m_s = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

// MD5 initial values
const std::array<uint32_t, 4> MD5Impl::m_iv = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

MD5Impl::MD5Impl() {
    reset();
}

void MD5Impl::reset() {
    m_block.fill(0);
    m_h = m_iv;
    m_index = 0;
    m_length = 0;
    m_state = HASH_INIT;
}

void MD5Impl::update(const char* const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_length += buflen * 8;
    m_state = HASH_UPDATE;

	while (offset < buflen) {
        m_block.at(m_index / 4) ^= MD5_ROL((uint32_t)buffer[offset], (m_index % 4) * 8);

		offset++;
        if ((++m_index % 64) == 0) {
            m_process_block();
            m_index = 0;
		}
	}
}

void MD5Impl::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append a padding bit
    m_block.at(m_index / 4) ^= MD5_ROL(0x80ul, (m_index % 4) * 8);

	// Process the block if the message length don't fit
    if ((8ull + m_index) >= 64)
        m_process_block();

	// Append the message length
    m_block.at(14) = m_length & 0xffffffff;
    m_block.at(15) = (m_length >> 32) & 0xffffffff;

    m_state = HASH_FINAL;
    m_process_block();
}

void MD5Impl::digest(unsigned char* const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < 16)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < 16; i++)
        *(output + i) = MD5_ROR(m_h.at(i / 4), (i % 4) * 8) & 0xff;
}

void MD5Impl::hexdigest(char* const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (outlen < 33)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < 16; i++)
        snprintf(output + (i * 2), 3, "%02x", MD5_ROR(m_h.at(i / 4), (i % 4) * 8) & 0xff);
}

void MD5Impl::m_process_block() {
    uint32_t a = m_h.at(0),
        b = m_h.at(1),
        c = m_h.at(2),
        d = m_h.at(3),
        f, g;
    unsigned i;

#if(DEBUG)
	// Debug
    fprintf(stderr, "__ m_block __\n");
    for (i = 0; i < m_block.size(); i++) {
        fprintf(stderr, "%08x ", m_block.at(i));
        if ((i + 1) % 4 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
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

        f = f + a + m_k.at(i) + m_block.at(g);
		a = d;
		d = c;
		c = b;
        b = b + MD5_ROL(f, m_s.at(i));
	}

    m_h.at(0) += a;
    m_h.at(1) += b;
    m_h.at(2) += c;
    m_h.at(3) += d;

    m_block.fill(0);
}

MD5::MD5() : pimpl(new MD5Impl()) {}

MD5::~MD5() {}

void MD5::reset() { pimpl->reset(); }

void MD5::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void MD5::finalize() { pimpl->finalize(); }

void MD5::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void MD5::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}
