#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/blake.h>

#define BLK_ROR(a, n) ROR((a), (n), sizeof(T) * 8)
#define BLK_ROL(a, n) ROL((a), (n), sizeof(T) * 8)

// BLAKE initial values
constexpr std::array<uint32_t, 8> IV224 = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<uint32_t, 8> IV256 = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<uint64_t, 8> IV384 = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};
constexpr std::array<uint64_t, 8> IV512 = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// BLAKE constants
const std::array<uint32_t, 16> K32 = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

const std::array<uint64_t, 16> K64 = {
    0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
};

constexpr std::array<std::array<unsigned, 16>, 10> SIGMA = {
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
    }
};

// BLAKE round constants
constexpr std::array<unsigned, 4> RC32 = {16, 12, 8, 7};
constexpr std::array<unsigned, 4> RC64 = {32, 25, 16, 11};

template<x32or64 T>
class Blake final : public HashImpl {
public:
    explicit Blake(unsigned bits);

    ~Blake() override = default;

    void reset() override;

    void update(const char* buffer, size_t buflen) override;

    void finalize() override;

    void digest(unsigned char* output, size_t outlen) override;

    void hexdigest(char* output, size_t outlen) override;

    [[maybe_unused]] void set_salt(const char* salt, size_t saltlen);

private:
    void m_process_block();

    void m_g(unsigned r, unsigned a, unsigned b, unsigned c, unsigned d, unsigned i);

    const std::array<T, 16>& m_k;
    const unsigned m_bits;
    const std::array<unsigned, 4> m_rc;

    std::array<T, 8> m_h{};
    std::array<T, (sizeof(T) == 4) ? 4 : 2> m_salt{};
    std::array<T, 16> m_block{};
    std::array<T, 16> m_v{};
    unsigned m_index{};
    size_t m_length{};
    HashState m_state{};
};

template<x32or64 T>
void Blake<T>::reset() {
    m_h.fill(0);
    m_salt.fill(0);
    m_block.fill(0);
    m_v.fill(0);
    m_index = 0;
    m_length = 0;
    m_state = HASH_INIT;

    if constexpr (sizeof(T) == 4) {
        switch (m_bits) {
            case 224:
                m_h = IV224;
                break;
            case 256:
                m_h = IV256;
                break;
            default:
                TC::error_invalid_bit_length();
        }
    } else {
        switch (m_bits) {
            case 384:
                m_h = IV384;
                break;
            case 512:
                m_h = IV512;
                break;
            default:
                TC::error_invalid_bit_length();
        }
    }
}

template<x32or64 T>
[[maybe_unused]] void Blake<T>::set_salt(const char* const salt, const size_t saltlen) {
    if (m_state > HASH_INIT)
        TC::error_salt_after_update();

    if (saltlen > 16)
        TC::error_invalid_salt_length();

    unsigned offset = 0;

    while (offset < saltlen) {
        m_salt.at(offset / sizeof(T)) ^= BLK_ROL((T)(salt[offset]), (offset % sizeof(T)) * 8);
        offset++;
    }
}

template<>
Blake<uint32_t>::Blake(const unsigned bits)
    : m_k(K32)
    , m_bits(bits / 8)
    , m_rc(RC32)
{
    if (bits % 8 > 0) TC::error_invalid_bit_length();

    reset();
}

template<>
Blake<uint64_t>::Blake(const unsigned bits)
    : m_k(K64)
    , m_bits(bits / 8)
    , m_rc(RC64)
{
    if (bits % 8 > 0) TC::error_invalid_bit_length();

    reset();
}

template<x32or64 T>
void Blake<T>::m_g(unsigned r, unsigned a, unsigned b, unsigned c, unsigned d, unsigned i) {
    T va = m_v.at(a);
    T vb = m_v.at(b);
    T vc = m_v.at(c);
    T vd = m_v.at(d);

    unsigned sri = SIGMA.at(r % 10).at(i);
    unsigned sri1 = SIGMA.at(r % 10).at(i + 1);

    va += vb + (m_block.at(sri) ^ m_k.at(sri1));
    vd = BLK_ROR(vd ^ va, m_rc.at(0));
    vc += vd;
    vb = BLK_ROR(vb ^ vc, m_rc.at(1));
    va += vb + (m_block.at(sri1) ^ m_k.at(sri));
    vd = BLK_ROR(vd ^ va, m_rc.at(2));
    vc += vd;
    vb = BLK_ROR(vb ^ vc, m_rc.at(3));

    m_v.at(a) = va;
    m_v.at(b) = vb;
    m_v.at(c) = vc;
    m_v.at(d) = vd;
}

template<x32or64 T>
void Blake<T>::m_process_block() {
    unsigned i, rounds;

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_block __\n");
    for (i = 0; i < m_block.size(); i++) {
        fprintf(
            stderr,
            "%0*llx ",
            (unsigned) (sizeof(T) * 2),
            (uint64_t) m_block.at(i)
            );
        if ((1ull + i) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    // Mix m_h into m_v
    for (i = 0; i < 8; i++) {
        m_v.at(i) = m_h.at(i);
        if (i < 4)
            m_v.at(i + 8) = m_salt.at(i % m_salt.size()) ^ m_k.at(i);
    }

    // Mix m_length into m_v
    if constexpr (sizeof(T) == 4) {
        // 32-bit
        m_v.at(12) = (m_length & 0xffffffff) ^ m_k.at(4);
        m_v.at(13) = (m_length & 0xffffffff) ^ m_k.at(5);
        m_v.at(14) = ((m_length >> 32) & 0xffffffff) ^ m_k.at(6);
        m_v.at(15) = ((m_length >> 32) & 0xffffffff) ^ m_k.at(7);

        rounds = 14;
    } else {
        // 64-bit
        m_v.at(12) = m_length ^ m_k.at(4);
        m_v.at(13) = m_length ^ m_k.at(5);
        m_v.at(14) = m_k.at(6);
        m_v.at(15) = m_k.at(7);

        rounds = 16;
    }

    // The round function
    for (i = 0; i < rounds; i++) {
        m_g(i, 0, 4, 8, 12, 0);
        m_g(i, 1, 5, 9, 13, 2);
        m_g(i, 2, 6, 10, 14, 4);
        m_g(i, 3, 7, 11, 15, 6);
        m_g(i, 0, 5, 10, 15, 8);
        m_g(i, 1, 6, 11, 12, 10);
        m_g(i, 2, 7, 8, 13, 12);
        m_g(i, 3, 4, 9, 14, 14);
    }

    // Store the results in m_h
    for (i = 0; i < 8; i++)
        m_h.at(i) ^= m_salt.at(i % m_salt.size()) ^ m_v.at(i) ^ m_v.at(i + 8);

    // Clear m_block
    m_block.fill(0);
}

template<x32or64 T>
void Blake<T>::update(const char* const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_length += buflen * 8;
    m_state = HASH_UPDATE;

    /* Copy every char in buffer into m_block, and process it
    when it gets full. */
    while (offset < buflen) {
        m_block.at(m_index / sizeof(T)) ^= BLK_ROR((T)(buffer[offset]), ((m_index + 1) % sizeof(T)) * 8);

        offset++;
        if ((++m_index % (16 * sizeof(T))) == 0) {
            m_process_block();
            m_index = 0;
        }
    }
}

template<x32or64 T>
void Blake<T>::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append a padding bit
    m_block.at(m_index / sizeof(T)) ^= BLK_ROR((T)0x80, ((m_index + 1) % sizeof(T)) * 8);

    // Process the block if the message length don't fit
    if (sizeof(T) * 2 + m_index - 1 >= 16 * sizeof(T))
        m_process_block();

    // Append an extra padding bit just before the length if
    // this is BLAKE256 or BLAKE512.
    if (m_bits == 32 || m_bits == 64)
        m_block.at(13) |= 1;

    // Append the length of the input in bits
    if constexpr (sizeof(T) == 4) {
        m_block.at(14) = m_length & (uint32_t) (-1);
        m_block.at(15) = (m_length >> 32) & (uint32_t) (-1);
    } else {
        m_block.at(15) = m_length;
    }

    m_state = HASH_FINAL;
    m_process_block();
}

template<x32or64 T>
void Blake<T>::digest(unsigned char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < m_bits)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    // Copy the raw bytes from m_h into the output buffer.
    for (unsigned i = 0; i < m_bits; i++)
        *(output + i) = BLK_ROL(m_h.at(i / sizeof(T)), ((i + 1) % sizeof(T)) * 8) & 0xff;
}

template<x32or64 T>
void Blake<T>::hexdigest(char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (outlen < m_bits * 2 + 1)
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    /* Copy the hex representation of the bytes in m_h into
    the output buffer. */
    for (unsigned i = 0; i < m_bits / sizeof(T); i++) {
        snprintf(
            output + (sizeof(T) * 2 * i),
            (sizeof(T) * 2) + 1,
            "%.*llx",
            (unsigned) (sizeof(T) * 2),
            (uint64_t) m_h.at(i)
        );
    }
}

// BLAKE224
BLAKE224::BLAKE224() : pimpl(new Blake<uint32_t>(224)) {}

BLAKE224::~BLAKE224() = default;

void BLAKE224::reset() { pimpl->reset(); }

void BLAKE224::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE224::finalize() { pimpl->finalize(); }

void BLAKE224::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE224::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE256
BLAKE256::BLAKE256() : pimpl(new Blake<uint32_t>(256)) {}

BLAKE256::~BLAKE256() = default;

void BLAKE256::reset() { pimpl->reset(); }

void BLAKE256::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE256::finalize() { pimpl->finalize(); }

void BLAKE256::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE256::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE384
BLAKE384::BLAKE384() : pimpl(new Blake<uint64_t>(384)) {}

BLAKE384::~BLAKE384() = default;

void BLAKE384::reset() { pimpl->reset(); }

void BLAKE384::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE384::finalize() { pimpl->finalize(); }

void BLAKE384::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE384::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// BLAKE512
BLAKE512::BLAKE512() : pimpl(new Blake<uint64_t>(512)) {}

BLAKE512::~BLAKE512() = default;

void BLAKE512::reset() { pimpl->reset(); }

void BLAKE512::update(const char* const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void BLAKE512::finalize() { pimpl->finalize(); }

void BLAKE512::digest(unsigned char* const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void BLAKE512::hexdigest(char* const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

