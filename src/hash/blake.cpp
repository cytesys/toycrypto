#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/blake.h>
#include <toycrypto/common/util.h>

// BLAKE initial values
constexpr std::array<uint32_t, 8> BLAKE224_IV = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<uint32_t, 8> BLAKE256_IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<uint64_t, 8> BLAKE384_IV = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};
constexpr std::array<uint64_t, 8> BLAKE512_IV = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// BLAKE constants
constexpr std::array<unsigned, 160> BLAKE_SIGMA = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
    11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
     7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
     9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
     2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
    12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
    13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
     6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
    10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0
};

template<>
const std::array<unsigned, 4> _BlakeImpl<uint32_t>::m_rc = {16, 12, 8, 7};

template<>
const std::array<uint32_t, 16> _BlakeImpl<uint32_t>::m_k = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

template<>
const std::array<unsigned, 4> _BlakeImpl<uint64_t>::m_rc = {32, 25, 16, 11};

template<>
const std::array<uint64_t, 16> _BlakeImpl<uint64_t>::m_k = {
    0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69
};

template<>
const unsigned _BlakeImpl<uint32_t>::m_rounds = 14;

template<>
const unsigned _BlakeImpl<uint64_t>::m_rounds = 16;

template<x32or64 T>
_BlakeImpl<T>::_BlakeImpl() {
    throw std::invalid_argument("Blake was instanciated with a wrong type");
}

template<x32or64 T>
_BlakeImpl<T>::~_BlakeImpl() = default;

template<>
_BlakeImpl<uint32_t>::_BlakeImpl() {}

template<>
_BlakeImpl<uint64_t>::_BlakeImpl() {}

template<x32or64 T>
void _BlakeImpl<T>::init_intermediate() {
    m_salt.fill(0);
}

template<x32or64 T>
void _BlakeImpl<T>::finalize() {
    if (this->get_digestsize() % 32 == 0)
        this->pad_haifa();
    else
        this->pad_md();
    this->append_length();
}

template<x32or64 T>
void _BlakeImpl<T>::set_salt(const char* const salt, const size_t saltlen) {
    if (this->get_phase() > HASH_INIT)
        throw std::invalid_argument("Cannot set salt after update");

    if (saltlen > 16)
        throw std::invalid_argument("Salt must be 16 bytes or less");

    unsigned offset = 0;

    while (offset < saltlen) {
        m_salt.at(offset / sizeof(T)) ^= ror_be<T>(salt[offset], offset);
        offset++;
    }
}

template<x32or64 T>
inline void _BlakeImpl<T>::blake_g(unsigned r, unsigned a, unsigned b, unsigned c, unsigned d, unsigned i) {
    T va = m_v.at(a);
    T vb = m_v.at(b);
    T vc = m_v.at(c);
    T vd = m_v.at(d);

    unsigned sri = BLAKE_SIGMA.at((r % 10) * 16 + i);
    unsigned sri1 = BLAKE_SIGMA.at((r % 10) * 16 + i + 1);

    va += vb + (this->m_block.at(sri) ^ m_k.at(sri1));
    vd = ror<T>(vd ^ va, m_rc.at(0));
    vc += vd;
    vb = ror<T>(vb ^ vc, m_rc.at(1));
    va += vb + (this->m_block.at(sri1) ^ m_k.at(sri));
    vd = ror<T>(vd ^ va, m_rc.at(2));
    vc += vd;
    vb = ror<T>(vb ^ vc, m_rc.at(3));

    m_v.at(a) = va;
    m_v.at(b) = vb;
    m_v.at(c) = vc;
    m_v.at(d) = vd;
}

template<x32or64 T>
void _BlakeImpl<T>::print_v() {
    fprintf(stderr, "__ m_v __\n");
    for (int i = 0; i < m_v.size(); i++) {
        fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) * 2), (uint64_t)(m_v.at(i)));
        if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

template<x32or64 T>
void _BlakeImpl<T>::process_block() {
    unsigned i;
    size_t length = this->get_length_bits();

#if(DEBUG)
    this->print_block();

#endif
    for (i = 0; i < 8; i++) {
        m_v.at(i) = this->m_state.at(i);
        m_v.at(i + 8) = m_k.at(i);
        if (i < 4)
            m_v.at(i + 8) ^= m_salt.at(i % m_salt.size());
    }

    // Append the message length in bits unless the current block only consists of padding.
    if (this->get_phase() != HASH_LAST) {
        if constexpr (std::is_same<T, uint32_t>::value) {
            // 32-bit
            m_v.at(12) ^= (length & 0xffffffff);
            m_v.at(13) ^= (length & 0xffffffff);
            m_v.at(14) ^= ((length >> 32) & 0xffffffff);
            m_v.at(15) ^= ((length >> 32) & 0xffffffff);
        } else {
            // 64-bit
            m_v.at(12) ^= length;
            m_v.at(13) ^= length;
        }
    }

    // The round function
    for (i = 0; i < m_rounds; i++) {
        blake_g(i, 0, 4, 8, 12, 0);
        blake_g(i, 1, 5, 9, 13, 2);
        blake_g(i, 2, 6, 10, 14, 4);
        blake_g(i, 3, 7, 11, 15, 6);
        blake_g(i, 0, 5, 10, 15, 8);
        blake_g(i, 1, 6, 11, 12, 10);
        blake_g(i, 2, 7, 8, 13, 12);
        blake_g(i, 3, 4, 9, 14, 14);
    }

    // Store the results in m_h
    for (i = 0; i < 8; i++)
        this->m_state.at(i) ^= m_salt.at(i % m_salt.size()) ^ m_v.at(i) ^ m_v.at(i + 8);

    this->clear_block();
}

template class _BlakeImpl<uint32_t>;
template class _BlakeImpl<uint64_t>;

BLAKE224::BLAKE224() {
    set_digestsize(28);
    reset();
}

void BLAKE224::init_state() {
    m_state.assign(BLAKE224_IV.begin(), BLAKE224_IV.end());
    init_intermediate();
}

BLAKE256::BLAKE256() {
    set_digestsize(32);
    reset();
}

void BLAKE256::init_state() {
    m_state.assign(BLAKE256_IV.begin(), BLAKE256_IV.end());
    init_intermediate();
}

BLAKE384::BLAKE384() {
    set_digestsize(48);
    reset();
}

void BLAKE384::init_state() {
    m_state.assign(BLAKE384_IV.begin(), BLAKE384_IV.end());
    init_intermediate();
}

BLAKE512::BLAKE512() {
    set_digestsize(64);
    reset();
}

void BLAKE512::init_state() {
    m_state.assign(BLAKE512_IV.begin(), BLAKE512_IV.end());
    init_intermediate();
}
