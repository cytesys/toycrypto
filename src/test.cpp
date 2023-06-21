#include <vector>
#include <concepts>
#include <string>
#include <algorithm>

#include <toycrypto/internal/common.h>
#include <toycrypto/common/util.h>
#include <toycrypto/hash/hash_common.h>

#define H_ROT_BE(i) ((((i) + 1) % sizeof(T)) * 8)
#define H_ROT_LE(i) (((i) % sizeof(T)) * 8)

#define H_ROR_BE(d, i) ROR((d), H_ROT_BE(i), sizeof(T) * 8)
#define H_ROR_LE(d, i) ROR((d), H_ROT_LE(i), sizeof(T) * 8)
#define H_ROL_BE(d, i) ROL((d), H_ROT_BE(i), sizeof(T) * 8)
#define H_ROL_LE(d, i) ROL((d), H_ROT_LE(i), sizeof(T) * 8)

template<typename T>
concept HBC = std::is_integral<T>::value;

template<HBC T, size_t BS, bool BE>
class HB {
public:
    // Virtual base class
    virtual ~HB() = 0;

    // This should be H specific
    // Unless H doesn't have any extra variables that need to be reset.
    virtual void reset();

    // This should be encapsulated better. The variables here are
    // endianness, bitwidth and blocksize.
    void update(const char* buffer, size_t buflen);

    // This should also be encapsulated better. The padding technique
    // can be a bit different, and endianness also plays a part here.
    virtual void finalize() = 0;

    // This can also be encapsulated better. The variables here are
    // endianness, digest size, bitwidth
    void digest(unsigned char* output, size_t outlen);

    std::string hexdigest();

protected:
    // This is H specific
    virtual void init_state() = 0;

    // This is H specific
    virtual void process_block() = 0;

    void pad_md();
    void pad_haifa();
    void append_length();

    std::vector<T> m_block{};
    std::vector<T> m_state{};
    size_t m_counter{};
    size_t m_length{};
    size_t m_digestsize{};
    HashState m_phase{};
};

template<HBC T, size_t BS, bool BE>
HB<T, BS, BE>::~HB() {}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::reset() {
    m_block.assign(BS, 0);
    m_counter = 0;
    m_length = 0;
    m_phase = HASH_INIT;

    init_state();
}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::update(const char* const buffer, const size_t buflen) {
    // Phase check
    if (m_phase > HASH_UPDATE)
        throw std::invalid_argument("Cannot update after final block");

    m_phase = HASH_UPDATE;

    size_t offset = 0;

    while (offset < buflen) {
        if constexpr (BE) {
            // Big endian
            m_block.at(m_counter / sizeof(T)) ^= H_ROR_BE((T)(buffer[offset]), m_counter);
        } else {
            // Little endian
            m_block.at(m_counter / sizeof(T)) ^= H_ROL_LE((T)(buffer[offset]), m_counter);
        }

        offset++;
        m_length++;
        if ((++m_counter % (BS * sizeof(T))) == 0) {
            m_counter += BS;
            process_block();
            m_counter = 0;
        }
    }
}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::pad_md() {
    if (m_phase >= HASH_FINAL)
        throw std::invalid_argument("Cannot pad after final block");

    // Append a padding bit
    if constexpr (BE) {
        // Big endian
        m_block.at(m_counter / sizeof(T)) ^= H_ROR_BE((T)0x80, m_counter);
    } else {
        // Little endian
        m_block.at(m_counter / sizeof(T)) ^= H_ROL_LE((T)0x80, m_counter);
    }
}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::pad_haifa() {
    pad_md();

    m_block.at(BS - 3) ^= 1; // See note below
}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::append_length() {
    if (m_phase >= HASH_FINAL)
        throw std::invalid_argument("Cannot append length after final block");

    // NOTE: Every hash function that I've seen that appends a message length
    // thus far, has either a 32-bit T or 64-bit T. In both cases the message
    // length is effectively put in the last two block "segments" of m_block.

    // Process the block if the message length don't fit.
    if (m_counter >= BS * sizeof(T) - (sizeof(T) * 2))
        process_block();

    // Append the length in bits
    m_length *= 8;

    // Append the message length
    if constexpr (BE) {
        m_block.at(BS - 1) = (T)m_length;
        if constexpr (sizeof(T) == 4) // See the note above
            m_block.at(BS - 2) = (T)(m_length >> 32);
    } else {
        m_block.at(BS - 2) = (T)m_length;
        if constexpr (sizeof(T) == 4) // See the note above
            m_block.at(BS - 1) = (T)(m_length >> 32);
    }

    m_phase = HASH_FINAL;
    process_block();
}

template<HBC T, size_t BS, bool BE>
void HB<T, BS, BE>::digest(unsigned char* const output, const size_t outlen) {
    if (m_phase < HASH_FINAL)
        throw std::invalid_argument("Cannot digest before final block");

    if (outlen < m_digestsize)
        throw std::invalid_argument("Output buffer size is too small");

    m_phase = HASH_DIGEST;

    for (unsigned i = 0; i < m_digestsize; i++) {
        if constexpr (BE)
            *(output + i) = H_ROL_BE(m_state.at(i / sizeof(T)), i) & 0xff;
        else
            *(output + i) = H_ROR_LE(m_state.at(i / sizeof(T)), i) & 0xff;
    }
}

template<HBC T, size_t BS, bool BE>
std::string HB<T, BS, BE>::hexdigest() {
    unsigned char* buffer = reinterpret_cast<unsigned char*>(
        calloc(m_digestsize, sizeof(unsigned char))
    );
    digest(buffer, m_digestsize);
    std::string result = TC::hexdigest(buffer, m_digestsize);
    free(buffer);
    return result;
}


// ---- SHA1 -----

#define SHA1_ROL(a, n) ROL((a), (n), 32)
#define SHA1_ROR(a, n) ROR((a), (n), 32)

// SHA1 initial values
constexpr std::array<uint32_t, 5> SHA1_IV = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

// SHA1 constants
constexpr std::array<uint32_t, 4> SHA1_K = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

class H final : public HB<uint32_t, 16, true> {
public:
    H();
    ~H () override = default;

    void finalize() override;

protected:
    void init_state() override;
    void process_block() override;

    std::array<uint32_t, 80> m_words;
};

void H::init_state() {
    m_state.assign(5, 0);
    std::copy(SHA1_IV.begin(), SHA1_IV.end(), m_state.begin());
}

H::H() {
    m_digestsize = 20;
    reset();
}

void H::finalize() {
    pad_md();
    append_length();
}

void H::process_block() {
    uint32_t a = m_state.at(0),
        b = m_state.at(1),
        c = m_state.at(2),
        d = m_state.at(3),
        e = m_state.at(4),
        f, k, tmp;

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
    for (i = 0; i < 80; i++) {
        if (i < 16) {
            m_words.at(i) = m_block.at(i);
        } else {
            m_words.at(i) = SHA1_ROL(
                m_words.at((-3ll) + i) ^ \
                m_words.at((-8ll) + i) ^ \
                m_words.at((-14ll) + i) ^ \
                m_words.at((-16ll) + i),
                1
            );
        }
    }

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = SHA1_K.at(0);
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = SHA1_K.at(1);
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = SHA1_K.at(2);
        } else {
            f = b ^ c ^ d;
            k = SHA1_K.at(3);
        }

        tmp = SHA1_ROL(a, 5) + f + e + k + m_words.at(i);
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = tmp;
    }

    m_state.at(0) += a;
    m_state.at(1) += b;
    m_state.at(2) += c;
    m_state.at(3) += d;
    m_state.at(4) += e;

    m_words.fill(0);
    m_block.assign(m_block.size(), 0);
}


int main(int argc, char** argv) {
    H test{};

    test.update("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 69);
    test.finalize();
    std::cout << test.hexdigest() << std::endl;

	return EXIT_SUCCESS;
}
