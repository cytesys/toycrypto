#include <toycrypto/internal/common.h>
#include <toycrypto/hash/sha3.h>

constexpr std::array<uint8_t, 25> KECCAK1600_K = {
    0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

// Precompute the round constants
consteval uint64_t k_rc(uint64_t t) {
    uint64_t result = 0x1;

    for (unsigned i = 1; i <= t; i++) {
        result <<= 1;
        if (result & 0x100) result ^= 0x71;
    }

    return result & 0x1;
}

consteval std::array<uint64_t, 24> keccak_rc() {
    std::array<uint64_t, 24> result{};

    uint64_t val;
    unsigned shift, i, x;
    for (i = 0; i < 24; i++) {
        shift = 1;
        val = 0;

        for (x = 0; x < 7; x++) {
            val |= k_rc(7 * i + x) << (shift - 1);
            shift *= 2;
        }

        result[i] = val;
    }

    return result;
}

constexpr std::array<uint64_t, 24> KECCAK1600_RC = keccak_rc();

inline size_t lane(size_t x, size_t y) { return (y * 5) + x; }

Keccak1600::Keccak1600(size_t capacity, uint8_t dsuf, size_t digestsize)
    : HBase(25, 200 - capacity)
    , m_capacity(capacity)
    , m_dsuf(dsuf)
{
    if (capacity == 0 || capacity >= 200)
        throw std::invalid_argument("Invalid capacity");

    if (digestsize == 0) {
        set_xof();
        digestsize++;
    }

    set_digestsize(digestsize);
    reset();
}

void Keccak1600::reset_subclass() {
    m_tmp.assign(25, 0);
    m_state.assign(25, 0);
}

void Keccak1600::finalize() {
    pad_byte(m_dsuf);

    if ((m_dsuf & 0x80) != 0 && get_index() == get_rate())
        process_block();

    m_block[get_rate() / 8 - 1] ^= 0x8000000000000000;
    set_enum(HASH_FINAL);
    process_block();
}

void Keccak1600::process_block() {
    unsigned i, x, y, shift;
    uint64_t d, result;

    // XOR the block with the internal state
    for (i = 0; i < m_state.size(); i++)
        m_state[i] ^= m_block[i];

    for (i = 0; i < 24; i++) {
        for (x = 0; x < 5; x++) {
            m_tmp[x] = m_state[lane(x, 0)] ^
                  m_state[lane(x, 1)] ^
                  m_state[lane(x, 2)] ^
                  m_state[lane(x, 3)] ^
                  m_state[lane(x, 4)];
        }

        for (x = 0; x < 5; x++) {
            d = m_tmp[(x + 4) % 5] ^ rol(m_tmp[(x + 1) % 5], 1);
            for (y = 0; y < 5; y++)
                m_state[lane(x, y)] ^= d;
        }

        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++)
                m_tmp[lane(y, ((2 * x) + (3 * y)) % 5)] =
                    rol(m_state[lane(x, y)], KECCAK1600_K[lane(x, y)]);
        }

        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                m_state[lane(x, y)] = m_tmp[lane(x, y)] ^
                    ((~m_tmp[lane((x + 1) % 5, y)]) & m_tmp[lane((x + 2) % 5, y)]);
            }
        }

        m_state[0] ^= KECCAK1600_RC[i];
    }

    clear_block();
}
