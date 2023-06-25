#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/blake2.h>
#include <toycrypto/common/util.h>

// Initial values
constexpr std::array<uint32_t, 8> BLAKE2_32_IV = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

constexpr std::array<uint64_t, 8> BLAKE2_64_IV = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Constants
constexpr std::array<unsigned, 160> BLAKE2_SIGMA = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
};

template<>
const std::array<uint32_t, 8>& _Blake2Impl<uint32_t>::m_k = BLAKE2_32_IV;

template<>
const std::array<uint64_t, 8>& _Blake2Impl<uint64_t>::m_k = BLAKE2_64_IV;

// Round constants
template<>
const std::vector<unsigned> _Blake2Impl<uint32_t>::m_rc = { 16, 12, 8, 7 };

template<>
const std::vector<unsigned> _Blake2Impl<uint64_t>::m_rc = { 32, 24, 16, 63 };

template<>
const unsigned _Blake2Impl<uint32_t>::m_rounds = 10;

template<>
const unsigned _Blake2Impl<uint64_t>::m_rounds = 12;

template<UTYPE T>
_Blake2Impl<T>::_Blake2Impl() {
    // Default constructor
    throw std::invalid_argument("Blake2 was instanciated with a wrong type");
}

template<>
_Blake2Impl<uint32_t>::_Blake2Impl() : HBase(16) {}

template<>
_Blake2Impl<uint64_t>::_Blake2Impl() : HBase(16) {}

template<UTYPE T>
void _Blake2Impl<T>::reset_subclass() {
    this->m_tmp.assign(16, 0);
    this->m_state.assign(m_k.begin(), m_k.end());

    this->m_state.at(0) ^= 0x01010000;
    this->m_state.at(0) ^= ((m_key.size() & 0xff) << 8);
    this->m_state.at(0) ^= (this->get_digestsize() & 0xff);
}

template<UTYPE T>
void _Blake2Impl<T>::finalize() {
    if (this->get_enum() >= HASH_FINAL)
        throw std::invalid_argument("Cannot call finalize more than once");

    if (this->get_counter() > 0 || this->get_length() == 0) {
        this->set_enum(HASH_FINAL);
        process_block();
    }
}

template<UTYPE T>
void _Blake2Impl<T>::blake2_g(unsigned i, unsigned a, unsigned b, unsigned c, unsigned d, unsigned x, unsigned y) {
    T va = this->m_tmp.at(a),
        vb = this->m_tmp.at(b),
        vc = this->m_tmp.at(c),
        vd = this->m_tmp.at(d);

    T xx = this->m_block.at(BLAKE2_SIGMA.at((i % 10) * 16 + x));
    T yy = this->m_block.at(BLAKE2_SIGMA.at((i % 10) * 16 + y));

    va += vb + xx;
    vd = ror<T>(vd ^ va, m_rc.at(0));
    vc += vd;
    vb = ror<T>(vb ^ vc, m_rc.at(1));
    va += vb + yy;
    vd = ror<T>(vd ^ va, m_rc.at(2));
    vc += vd;
    vb = ror<T>(vb ^ vc, m_rc.at(3));

    this->m_tmp.at(a) = va;
    this->m_tmp.at(b) = vb;
    this->m_tmp.at(c) = vc;
    this->m_tmp.at(d) = vd;
}

template<UTYPE T>
void _Blake2Impl<T>::process_block() {
    unsigned i;

#if(DEBUG)
    this->print_block();

#endif
    // Initialize local work vector
    for (i = 0; i < 8; i++) {
        this->m_tmp.at(i) = this->m_state.at(i);
        this->m_tmp.at(8 + i) = m_k.at(i);
    }

    // Mix in the message length
    this->m_tmp.at(12) ^= (T)(this->get_length());
    if constexpr (std::is_same<T, uint32_t>::value)
        this->m_tmp.at(13) ^= (T)((this->get_length() >> 32) & 0xffffffff);

    // Complement m_v[14] if this is the final block
    if (this->get_enum() == HASH_FINAL)
        this->m_tmp.at(14) = ~this->m_tmp.at(14);

#if(DEBUG)
    this->print_tmp();

#endif
    // ChaCha quarter round function
    for (i = 0; i < m_rounds; i++) {
        blake2_g(i, 0, 4, 8, 12, 0, 1);
        blake2_g(i, 1, 5, 9, 13, 2, 3);
        blake2_g(i, 2, 6, 10, 14, 4, 5);
        blake2_g(i, 3, 7, 11, 15, 6, 7);

        blake2_g(i, 0, 5, 10, 15, 8, 9);
        blake2_g(i, 1, 6, 11, 12, 10, 11);
        blake2_g(i, 2, 7, 8, 13, 12, 13);
        blake2_g(i, 3, 4, 9, 14, 14, 15);
    }

    // Mix the working array into the internal state
    for (i = 0; i < 8; i++)
        this->m_state.at(i) ^= this->m_tmp.at(i) ^ this->m_tmp.at(8 + i);

    // Empty m_block
    this->clear_block();
}

template class _Blake2Impl<uint32_t>;
template class _Blake2Impl<uint64_t>;

BLAKE2s::BLAKE2s(unsigned digestbits) {
    if (digestbits % 8 > 0 || digestbits < 8 || digestbits > 256)
        throw std::invalid_argument("Invalid digest bitlength for BLAKE2S");

    set_digestsize(digestbits / 8);
}

BLAKE2b::BLAKE2b(unsigned digestbits) {
    if (digestbits % 8 > 0 || digestbits < 8 || digestbits > 512)
        throw std::invalid_argument("Invalid digest bitlength for BLAKE2B");

    set_digestsize(digestbits / 8);
}
