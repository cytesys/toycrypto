#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/sha2.h>

#define SHA2_ROR(a, n) ROR((a), (n), sizeof(T) * 8)
#define SHA2_ROL(a, n) ROL((a), (n), sizeof(T) * 8)
#define SHA2_K_SIZE ((sizeof(T) == 8) ? 80 : 64)

// SHA2 initial values
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

// TODO: Generate these tables automatically for different subtypes
//constexpr std::array<uint64_t, 8> IV512_224 = {
//	0x8c3d37c819544da2, 0x73e1996689dcd4d6,
//	0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
//	0x0f6d2b697bd44da8, 0x77e36f7304c48942,
//	0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
//};
//constexpr std::array<uint64_t, 8> IV512_256 = {
//	0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
//	0x2393b86b6f53b151, 0x963877195940eabd,
//	0x96283ee2a88effe3, 0xbe5e1e2553863992,
//	0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
//};

// SHA2 constants
constexpr std::array<uint32_t, 64> K32 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

constexpr std::array<uint64_t, 80> K64 = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// SHA2 round constants
constexpr std::array<unsigned, 12> RC32 = {
    7, 18, 3, 17, 19, 10, 2, 13, 22, 6, 11, 25
};

constexpr std::array<unsigned, 12> RC64 = {
    1, 8, 7, 19, 61, 6, 28, 34, 39, 14, 18, 41
};

template<x32or64 T>
class SHA2 final : public HashImpl {
public:
    explicit SHA2(unsigned bits);

    ~SHA2() override = default;

    void reset() override;

    void update(const char *buffer, size_t buflen) override;

    void finalize() override;

    void digest(unsigned char *output, size_t outlen) override;

    void hexdigest(char *output, size_t outlen) override;

private:
    void m_process_block();

    const std::array<unsigned, 12> &m_rc;
    const std::array<T, SHA2_K_SIZE> &m_k;
    const unsigned m_bits;

    std::array<T, 8> m_h{};
    std::array<T, SHA2_K_SIZE> m_words{};
    size_t m_length{};
    unsigned m_index{};
    HashState m_state{};
};

template<x32or64 T>
void SHA2<T>::reset() {
    m_words.fill(0);
    m_length = 0;
    m_index = 0;
    m_state = HASH_INIT;

    if constexpr (sizeof(T) == 4) {
        // 32-bit
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
        // 64-bit
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

template<>
SHA2<uint32_t>::SHA2(unsigned bits)
    : m_rc(RC32)
    , m_k(K32)
    , m_bits(bits) { reset(); }

template<>
SHA2<uint64_t>::SHA2(unsigned bits)
    : m_rc(RC64)
    , m_k(K64)
    , m_bits(bits) { reset(); }

template<x32or64 T>
void SHA2<T>::update(const char *const buffer, const size_t buflen) {
    if (m_state > HASH_UPDATE)
        TC::error_update_after_finalize();

    size_t offset = 0;

    m_length += buflen * 8;
    m_state = HASH_UPDATE;

    while (offset < buflen) {
        m_words.at(m_index / sizeof(T)) ^= SHA2_ROR((T) buffer[offset], ((m_index + 1) % sizeof(T)) * 8);

        offset++;
        if ((++m_index % (16 * sizeof(T))) == 0) {
            m_process_block();
            m_index = 0;
        }
    }
}

template<x32or64 T>
void SHA2<T>::finalize() {
    if (m_state >= HASH_FINAL)
        TC::error_finalize_after_finalize();

    // Append a padding bit
    m_words.at(m_index / sizeof(T)) ^= SHA2_ROR((T) 0x80, ((m_index + 1) % sizeof(T)) * 8);

    // Process the block if the message length don't fit
    if (sizeof(T) * 2 + m_index >= 16 * sizeof(T))
        m_process_block();

    // Append the message length
    m_words.at(15) = (T)m_length;
    if constexpr (sizeof(T) == 4)
        m_words.at(14) = (T)(m_length >> 32);

    m_state = HASH_FINAL;
    m_process_block();
}

template<x32or64 T>
void SHA2<T>::digest(unsigned char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_digest_before_finalize();

    if (outlen < (m_bits / 8))
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < (m_bits / 8); i++)
        *(output + i) = SHA2_ROL(m_h.at(i / sizeof(T)), ((i + 1) % sizeof(T)) * 8) & 0xff;
}

template<x32or64 T>
void SHA2<T>::hexdigest(char *const output, const size_t outlen) {
    if (m_state < HASH_FINAL)
        TC::error_hexdigest_before_finalize();

    if (outlen < (m_bits / 4 + 1))
        TC::error_invalid_output_length();

    m_state = HASH_DIGEST;

    for (unsigned i = 0; i < (m_bits / (sizeof(T) * 8)); i++) {
        snprintf(
            output + (sizeof(T) * 2 * i),
            (sizeof(T) * 2) + 1,
            "%.*llx",
            (unsigned) (sizeof(T) * 2),
            (uint64_t) m_h.at(i)
        );
    }
}

template<x32or64 T>
void SHA2<T>::m_process_block() {
    T a = m_h.at(0),
        b = m_h.at(1),
        c = m_h.at(2),
        d = m_h.at(3),
        e = m_h.at(4),
        f = m_h.at(5),
        g = m_h.at(6),
        h = m_h.at(7),
        s0, s1, ch, maj,
        tmp1, tmp2;

    unsigned i;

#if(DEBUG)
    // Debug
    fprintf(stderr, "__ m_block __\n");
    for (i = 0; i < 16; i++) {
        fprintf(stderr, "%.*llx ", (unsigned) (sizeof(T) * 2), (uint64_t) m_words.at(i));
        if ((1ull + i) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

#endif
    // Expand the 16 first bytes (aka the new block)
    for (i = 16; i < m_k.size(); i++) {
        s0 = SHA2_ROR(m_words.at((-15ll) + i), m_rc.at(0)) ^
             SHA2_ROR(m_words.at((-15ll) + i), m_rc.at(1)) ^
             (m_words.at((-15ll) + i) >> m_rc.at(2));
        s1 = SHA2_ROR(m_words.at((-2ll) + i), m_rc.at(3)) ^
             SHA2_ROR(m_words.at((-2ll) + i), m_rc.at(4)) ^
             (m_words.at((-2ll) + i) >> m_rc.at(5));
        m_words.at(i) = m_words.at((-16ll) + i) + s0 + m_words.at((-7ll) + i) + s1;
    }

    // Main compression loop
    for (i = 0; i < m_k.size(); i++) {
        s0 = SHA2_ROR(a, m_rc.at(6)) ^ SHA2_ROR(a, m_rc.at(7)) ^ SHA2_ROR(a, m_rc.at(8));
        s1 = SHA2_ROR(e, m_rc.at(9)) ^ SHA2_ROR(e, m_rc.at(10)) ^ SHA2_ROR(e, m_rc.at(11));
        ch = (e & f) ^ (~e & g);
        tmp1 = h + s1 + ch + m_k.at(i) + m_words.at(i);
        maj = (a & b) ^ (a & c) ^ (b & c);
        tmp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;

    }

    // Add the compressed chunk to the current hash value
    m_h.at(0) += a;
    m_h.at(1) += b;
    m_h.at(2) += c;
    m_h.at(3) += d;
    m_h.at(4) += e;
    m_h.at(5) += f;
    m_h.at(6) += g;
    m_h.at(7) += h;

    m_words.fill(0);
}

// SHA224
SHA224::SHA224() : pimpl(new SHA2<uint32_t>(224)) {}

SHA224::~SHA224() = default;

void SHA224::reset() { pimpl->reset();}

void SHA224::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA224::finalize() { pimpl->finalize(); }

void SHA224::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA224::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA256
SHA256::SHA256() : pimpl(new SHA2<uint32_t>(256)) {}

SHA256::~SHA256() = default;

void SHA256::reset() { pimpl->reset(); }

void SHA256::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA256::finalize() { pimpl->finalize(); }

void SHA256::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA256::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA384
SHA384::SHA384() : pimpl(new SHA2<uint64_t>(384)) {}

SHA384::~SHA384() = default;

void SHA384::reset() { pimpl->reset(); }

void SHA384::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA384::finalize() { pimpl->finalize(); }

void SHA384::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA384::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}

// SHA512
SHA512::SHA512() : pimpl(new SHA2<uint64_t>(512)) {}

SHA512::~SHA512() = default;

void SHA512::reset() { pimpl->reset(); }

void SHA512::update(const char *const buffer, const size_t buflen) {
    pimpl->update(buffer, buflen);
}

void SHA512::finalize() { pimpl->finalize(); }

void SHA512::digest(unsigned char *const output, const size_t outlen) {
    pimpl->digest(output, outlen);
}

void SHA512::hexdigest(char *const output, const size_t outlen) {
    pimpl->hexdigest(output, outlen);
}
