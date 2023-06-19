#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/sha3.h>

#define LANE(x, y) (((y) * 5) + (x))
#define SHA3_ROR(a, n) ROR((a), (n), 64)
#define SHA3_ROL(a, n) ROL((a), (n), 64)

constexpr std::array<uint8_t, 25> RO = {
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14
};

class Keccak1600 final : public HashImpl {
public:
    explicit Keccak1600(unsigned capacity, uint8_t dsuf, unsigned bitlength);
    ~Keccak1600() override = default;

    void reset() override ;
    void update(const char* buffer, size_t buflen) override;
    void finalize() override;
    void digest(unsigned char* output, size_t outlen) override;
    void hexdigest(char* output, size_t outlen) override;

private:
    const unsigned m_rate;
    const uint64_t m_dsuf;
    const unsigned m_bytes;

    std::array<uint64_t, 25> m_h{};
    std::array<uint64_t, 25> m_b{};
    std::array<uint64_t, 5> m_c{};
    unsigned m_index{};
    HashState m_state{};

    static uint64_t m_rc(size_t t);

    void m_keccakf();
};

uint64_t Keccak1600::m_rc(size_t t) {
    uint64_t result = 0x1;

    for (unsigned i = 1; i <= t; i++) {
        result <<= 1;
        if (result & 0x100) result ^= 0x71;
    }

    return result & 0x1;
}

Keccak1600::Keccak1600(unsigned capacity, uint8_t dsuf, unsigned bitlength)
    : m_rate((1600 - capacity) / 8)
    , m_dsuf(dsuf)
    , m_bytes(bitlength / 8)
{
    if ((capacity % 8) != 0)
        throw std::invalid_argument("The supplied capacity is invalid");

    if ((bitlength % 8) != 0)
        TC::error_invalid_bit_length();
}

void Keccak1600::reset() {
    m_h.fill(0);
    m_b.fill(0);
    m_c.fill(0);
    m_index = 0;
    m_state = HASH_INIT;
}

void Keccak1600::m_keccakf() {
    unsigned i, x, y, shift;
    uint64_t d, result;

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_h (before) __\n");
    for (i = 0; i < m_h.size(); i++) {
        fprintf(stderr, "%016llx ", m_h.at(i));
        if ((i + 1) % 2 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    for (i = 0; i < 24; i++) {
		for (x = 0; x < 5; x++) {
            m_c.at(x) = m_h.at(LANE(x, 0)) ^
                      m_h.at(LANE(x, 1)) ^
                      m_h.at(LANE(x, 2)) ^
                      m_h.at(LANE(x, 3)) ^
                      m_h.at(LANE(x, 4));
		}

		for (x = 0; x < 5; x++) {
            d = m_c.at((x + 4) % 5) ^ SHA3_ROL(m_c.at((x + 1) % 5), 1);
            for (y = 0; y < 5; y++)
                m_h.at(LANE(x, y)) ^= d;
		}

		for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++)
                m_b.at(LANE(y, ((2 * x) + (3 * y)) % 5)) = SHA3_ROL(m_h.at(LANE(x, y)), RO.at(LANE(x, y)));
		}

		for (y = 0; y < 5; y++) {
			for (x = 0; x < 5; x++) {
                m_h.at(LANE(x, y)) = m_b.at(LANE(x, y)) ^ ((~m_b.at(LANE((x + 1) % 5, y))) & m_b.at(LANE((x + 2) % 5, y)));
			}
		}

        result = 0;
        shift = 1;
        for (x = 0; x < 7; x++) {
            result |= m_rc(7 * i + x) << (shift - 1);
			shift *= 2;
		}
        m_h.at(0) ^= result;
    }

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_h (after) __\n");
    for (i = 0; i < m_h.size(); i++) {
        fprintf(stderr, "%016llx ", m_h.at(i));
        if ((i + 1) % 2 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    m_b.fill(0);
    m_c.fill(0);
}

void Keccak1600::update(const char* const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_state = HASH_UPDATE;

    while (offset < buflen) {
        m_h.at(m_index / 8) ^= SHA3_ROL((uint64_t)buffer[offset], (m_index % 8) * 8);

        offset++;
        if (++m_index == m_rate) {
            m_keccakf();
            m_index = 0;
		}
    }
}

void Keccak1600::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append padding
    m_h.at(m_index / 8) ^= SHA3_ROL(m_dsuf, (m_index % 8) * 8);

    if ((m_dsuf & 0x80) != 0 && (m_index + 1) == m_rate)
        m_keccakf();

    m_h.at((m_rate / 8) - 1) ^= 0x8000000000000000;
    m_state = HASH_FINAL;
    m_keccakf();
}

void Keccak1600::digest(unsigned char* const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (m_state > HASH_FINAL) {
        throw std::invalid_argument(
            "Cannot calculate this digest twice, due to changes in the internal state."
        );
    }

    if (outlen < m_bytes)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < m_bytes; i++) {
        *(output + i) = (uint8_t)SHA3_ROR(m_h.at((i / 8) % (m_rate / 8)), (i % 8) * 8) & 0xff;
        if ((i + 1) % m_rate == 0) m_keccakf();
    }
}

void Keccak1600::hexdigest(char* const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (m_state > HASH_FINAL) {
        throw std::invalid_argument(
            "Cannot calculate this digest twice, due to changes in the internal state."
        );
    }

    if (outlen < (m_bytes * 2 + 1))
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < m_bytes; i++) {
        snprintf(
            output + (i * 2),
            3,
            "%02x",
            (uint8_t)(SHA3_ROR(m_h.at((i / 8) % (m_rate / 8)), (i % 8) * 8) & 0xff)
        );
        if ((i + 1) % m_rate == 0) m_keccakf();
    }
}

// SHA3-224
SHA3_224::SHA3_224() : pimpl(new Keccak1600(448, 6, 224)) {}

SHA3_224::~SHA3_224() = default;

void SHA3_224::reset() { pimpl->reset(); }

void SHA3_224::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA3_224::finalize() { pimpl->finalize(); }

void SHA3_224::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA3_224::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA3-256
SHA3_256::SHA3_256() : pimpl(new Keccak1600(512, 6, 256)) {}

SHA3_256::~SHA3_256() = default;

void SHA3_256::reset() { pimpl->reset(); }

void SHA3_256::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA3_256::finalize() { pimpl->finalize(); }

void SHA3_256::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA3_256::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA3-384
SHA3_384::SHA3_384() : pimpl(new Keccak1600(768, 6, 384)) {}

SHA3_384::~SHA3_384() = default;

void SHA3_384::reset() { pimpl->reset(); }

void SHA3_384::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA3_384::finalize() { pimpl->finalize(); }

void SHA3_384::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA3_384::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA3-512
SHA3_512::SHA3_512() : pimpl(new Keccak1600(1024, 6, 512)) {}

SHA3_512::~SHA3_512() = default;

void SHA3_512::reset() { pimpl->reset(); }

void SHA3_512::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA3_512::finalize() { pimpl->finalize(); }

void SHA3_512::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA3_512::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHAKE128
SHAKE128::SHAKE128(unsigned digestbits)
    : pimpl(new Keccak1600(256, 0x1f, digestbits)) {}

SHAKE128::~SHAKE128() = default;

void SHAKE128::reset() { pimpl->reset(); }

void SHAKE128::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHAKE128::finalize() { pimpl->finalize(); }

void SHAKE128::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHAKE128::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHAKE256
SHAKE256::SHAKE256(unsigned digestbits)
    : pimpl(new Keccak1600(512, 0x1f, digestbits)) {}

SHAKE256::~SHAKE256() = default;

void SHAKE256::reset() { pimpl->reset(); }

void SHAKE256::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHAKE256::finalize() { pimpl->finalize(); }

void SHAKE256::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHAKE256::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}
