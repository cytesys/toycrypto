#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/blake2.h>

// Initial values
constexpr std::array<uint32_t, 8> IV32 = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

constexpr std::array<uint64_t, 8> IV64 = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Constants
constexpr std::array<std::array<unsigned int, 16>, 10> SIGMA = {{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } ,
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 } ,
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 } ,
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 } ,
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 } ,
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 } ,
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 } ,
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 } ,
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 } ,
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
}};

// Round constants
constexpr std::array<unsigned, 4> RC32 = {
    16, 12, 8, 7
};

constexpr std::array<unsigned, 4> RC64 = {
    32, 24, 16, 63
};

template<x32or64 T>
class Blake2 final : public HashImpl {
public:
    explicit Blake2(unsigned bitlength);
    ~Blake2() override = default;

    void reset() override;
    void update(const char* buffer, size_t buflen) override;
    void finalize() override;
    void digest(unsigned char* output, size_t outlen) override;
    void hexdigest(char* output, size_t outlen) override;

private:
    const std::array<unsigned, 4> m_rc;
    const std::array<T, 8>& m_iv;
    const unsigned m_bits;

    std::array<T, 16> m_block{};
    std::array<T, 16> m_v{};
    std::array<T, 8> m_h{};
    T m_keylen{};

    size_t m_length{};
    unsigned m_index{};
    HashState m_state{};

    void m_process_block();
    void m_G(unsigned i, unsigned a, unsigned b, unsigned c, unsigned d, unsigned x, unsigned y);
};

template<x32or64 T>
void Blake2<T>::reset() {
    m_block.fill(0);
    m_v.fill(0);
    m_length = 0;
    m_index = 0;
    m_keylen = 0;
    m_state = HASH_INIT;
    m_h = m_iv;

    // Set parameters
    m_h.at(0) ^= 0x01010000 ^ ((m_keylen & 0xff) << 8) ^ ((m_bits / 8) & 0xff);
}

template<>
Blake2<uint32_t>::Blake2(unsigned bitlength)
    : m_rc(RC32)
    , m_iv(IV32)
    , m_bits(bitlength)
{
    if (m_bits % 8 > 0 || m_bits > 256)
        TC::error_invalid_bit_length();

    reset();
}

template<>
Blake2<uint64_t>::Blake2(unsigned bitlength)
    : m_rc(RC64)
    , m_iv(IV64)
    , m_bits(bitlength)
{
    if (m_bits % 8 > 0 || m_bits > 512)
        TC::error_invalid_bit_length();

    reset();
}

template<x32or64 T>
void Blake2<T>::m_G(unsigned i, unsigned a, unsigned b, unsigned c, unsigned d, unsigned x, unsigned y) {
    const unsigned t = sizeof(T) * 8;

    T va = m_v.at(a);
    T vb = m_v.at(b);
    T vc = m_v.at(c);
    T vd = m_v.at(d);

    T xx = m_block.at(SIGMA.at(i % 10).at(x));
    T yy = m_block.at(SIGMA.at(i % 10).at(y));

    va += vb + xx;
    vd = ROR(vd ^ va, m_rc.at(0), t);
    vc += vd;
    vb = ROR(vb ^ vc, m_rc.at(1), t);
    va += vb + yy;
    vd = ROR(vd ^ va, m_rc.at(2), t);
    vc += vd;
    vb = ROR(vb ^ vc, m_rc.at(3), t);

    m_v.at(a) = va;
    m_v.at(b) = vb;
    m_v.at(c) = vc;
    m_v.at(d) = vd;
}

template<x32or64 T>
void Blake2<T>::m_process_block() {
    unsigned i, r;

    if constexpr (std::is_same<T, uint32_t>::value) {
        // 32-bit
        r = 10;
    } else {
        // 64-bit
        r = 12;
    }

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_block __\n");
    for (i = 0; i < m_block.size(); i++) {
        fprintf(stderr, "%.*llx ", (unsigned) (sizeof(T) * 2), (uint64_t) m_block.at(i));
        if ((1ull + i) % (16 / sizeof(T)) == 0) {
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "\n");

#endif
    // Initialize local work vector
    for (i = 0; i < 8; i++) {
        m_v.at(i) = m_h.at(i);
        m_v.at(8 + i) = m_iv.at(i);
    }

    // Mix in m_length
    m_v.at(12) ^= (T)(m_length);
    if constexpr (std::is_same<T, uint32_t>::value)
        // 32-bit
        m_v.at(13) ^= (m_length >> 32) & 0xffffffff;

    // Complement m_v[14] if this is the final block
    if (m_state == HASH_FINAL)
        m_v.at(14) = ~m_v.at(14);

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_v __\n");
    for (i = 0; i < m_v.size(); i++) {
        fprintf(stderr, "%.*llx ", (unsigned) (sizeof(T) * 2), (uint64_t) m_v.at(i));
        if ((1ull + i) % (16 / sizeof(T)) == 0)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    // Cryptographic mixing
    for (i = 0; i < r; i++) {
        m_G(i, 0, 4, 8, 12, 0, 1);
        m_G(i, 1, 5, 9, 13, 2, 3);
        m_G(i, 2, 6, 10, 14, 4, 5);
        m_G(i, 3, 7, 11, 15, 6, 7);

        m_G(i, 0, 5, 10, 15, 8, 9);
        m_G(i, 1, 6, 11, 12, 10, 11);
        m_G(i, 2, 7, 8, 13, 12, 13);
        m_G(i, 3, 4, 9, 14, 14, 15);
    }

    // Mix the local work vector (m_v) into the internal state (m_h)
    for (i = 0; i < 8; i++)
        m_h.at(i) ^= m_v.at(i) ^ m_v.at(8 + i);

    // Empty m_block
    m_block.fill(0);
}

template<x32or64 T>
void Blake2<T>::update(const char *const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;
    const size_t t = sizeof(T);

    m_state = HASH_UPDATE;

    while (offset < buflen) {
        m_block.at(m_index / t) |= ROL((T)buffer[offset], (m_index % t) * 8, t * 8);
        m_length++;
        offset++;
        if ((++m_index % (16 * t)) == 0) {
            m_process_block();
            m_index %= (16 * t);
        }
    }
}

template<x32or64 T>
void Blake2<T>::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    m_state = HASH_FINAL;

    m_process_block();
}

template<x32or64 T>
void Blake2<T>::digest(unsigned char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < (m_bits / 8))
        TC::error_invalid_output_length();

    const size_t t = sizeof(T);

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < (m_bits / 8); i++)
        *(output + i) = ROR(m_h.at(i / t), (i % t) * 8, t * 8) & 0xff;
}

template<x32or64 T> void Blake2<T>::hexdigest(char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (outlen < (m_bits / 4 + 1))
        TC::error_invalid_output_length();

    const size_t t = sizeof(T);

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < (m_bits / 8); i++) {
        snprintf(
            output + (i * 2),
            3,
            "%02x",
            (uint8_t)(ROR(m_h.at(i / t), (i % t) * 8, t * 8) & 0xff)
            );
    }
}

// BLAKE2S_224
BLAKE2S_224::BLAKE2S_224() : pimpl(new Blake2<uint32_t>(224)) {}

BLAKE2S_224::~BLAKE2S_224() = default;

void BLAKE2S_224::reset() { pimpl->reset(); }

void BLAKE2S_224::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE2S_224::finalize() { pimpl->finalize(); }

void BLAKE2S_224::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE2S_224::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE2S_256
BLAKE2S_256::BLAKE2S_256() : pimpl(new Blake2<uint32_t>(256)) {}

BLAKE2S_256::~BLAKE2S_256() = default;

void BLAKE2S_256::reset() { pimpl->reset(); }

void BLAKE2S_256::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE2S_256::finalize() { pimpl->finalize(); }

void BLAKE2S_256::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE2S_256::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE2B_384
BLAKE2B_384::BLAKE2B_384() : pimpl(new Blake2<uint64_t>(384)) {}

BLAKE2B_384::~BLAKE2B_384() = default;

void BLAKE2B_384::reset() { pimpl->reset(); }

void BLAKE2B_384::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE2B_384::finalize() { pimpl->finalize(); }

void BLAKE2B_384::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE2B_384::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE2B_512
BLAKE2B_512::BLAKE2B_512() : pimpl(new Blake2<uint64_t>(512)) {}

BLAKE2B_512::~BLAKE2B_512() = default;

void BLAKE2B_512::reset() { pimpl->reset(); }

void BLAKE2B_512::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE2B_512::finalize() { pimpl->finalize(); }

void BLAKE2B_512::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE2B_512::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}
