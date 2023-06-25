#include <toycrypto/internal/common.h>
#include <toycrypto/hash/sha3.h>

constexpr std::array<uint8_t, 25> KECCAK1600_K = {
    0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

size_t Keccak1600::lane(size_t x, size_t y) { return (y * 5) + x; }

uint64_t Keccak1600::m_rc(size_t t) {
    uint64_t result = 0x1;
    int i;

    for (i = 1; i <= t; i++) {
        result <<= 1;
        if (result & 0x100) result ^= 0x71;
    }

    return result & 0x1;
}

Keccak1600::Keccak1600(size_t capacity, uint8_t dsuf, size_t digestsize)
    : HBase(25, 200 - capacity)
    , m_capacity(capacity)
    , m_dsuf(dsuf)
{
    if (capacity <= 0 || capacity >= 200)
        throw std::invalid_argument("Invalid capacity");

    if (digestsize < 0)
        throw std::invalid_argument("Invalid digest bitlength");

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

    m_block.at(get_rate() / 8 - 1) ^= 0x8000000000000000;
    set_enum(HASH_FINAL);
    process_block();
}

void Keccak1600::process_block() {
    unsigned i, x, y, shift;
    uint64_t d, result;

    // XOR the internal state with the block
    for (i = 0; i < m_state.size(); i++) {
        m_state.at(i) ^= m_block.at(i);
    }

#if(DEBUG)
    print_state();

#endif
    for (i = 0; i < 24; i++) {
        for (x = 0; x < 5; x++) {
            m_tmp.at(x) = m_state.at(lane(x, 0)) ^
                      m_state.at(lane(x, 1)) ^
                      m_state.at(lane(x, 2)) ^
                      m_state.at(lane(x, 3)) ^
                      m_state.at(lane(x, 4));
        }

        for (x = 0; x < 5; x++) {
            d = m_tmp.at((x + 4) % 5) ^ rol<uint64_t>(m_tmp.at((x + 1) % 5), 1);
            for (y = 0; y < 5; y++)
                m_state.at(lane(x, y)) ^= d;
        }

        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++)
                m_tmp.at(lane(y, ((2 * x) + (3 * y)) % 5)) =
                    rol<uint64_t>(m_state.at(lane(x, y)), KECCAK1600_K.at(lane(x, y)));
        }

        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                m_state.at(lane(x, y)) = m_tmp.at(lane(x, y)) ^
                    ((~m_tmp.at(lane((x + 1) % 5, y))) & m_tmp.at(lane((x + 2) % 5, y)));
            }
        }

        result = 0;
        shift = 1;
        for (x = 0; x < 7; x++) {
            result |= m_rc(7 * i + x) << (shift - 1);
            shift *= 2;
        }
        m_state.at(0) ^= result;
    }

#if(DEBUG)
    print_state();

#endif

    clear_block();
}
