#include <toycrypto/internal/common.h>
#include <toycrypto/internal/exceptions.h>
#include <toycrypto/hash/sha2.h>
#include <toycrypto/common/util.h>

// SHA2 initial values
constexpr std::array<uint32_t, 8> SHA224_IV = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

constexpr std::array<uint32_t, 8> SHA256_IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

constexpr std::array<uint64_t, 8> SHA384_IV = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

constexpr std::array<uint64_t, 8> SHA512_IV = {
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
template<>
const std::vector<uint32_t> _Sha2Impl<uint32_t>::m_k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

template <>
const std::vector<uint64_t> _Sha2Impl<uint64_t>::m_k = {
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
template<>
const std::array<unsigned, 12> _Sha2Impl<uint32_t>::m_rc = {
    7, 18, 3, 17, 19, 10, 2, 13, 22, 6, 11, 25
};

template<>
const std::array<unsigned, 12> _Sha2Impl<uint64_t>::m_rc = {
    1, 8, 7, 19, 61, 6, 28, 34, 39, 14, 18, 41
};

template<x32or64 T>
_Sha2Impl<T>::_Sha2Impl() {
    throw std::invalid_argument("Sha2 was instanciated with a wrong type");
}

template<x32or64 T>
_Sha2Impl<T>::~_Sha2Impl() = default;

template<>
_Sha2Impl<uint32_t>::_Sha2Impl() {}

template<>
_Sha2Impl<uint64_t>::_Sha2Impl() {}

template<x32or64 T>
void _Sha2Impl<T>::init_intermediate() {
    m_v.assign(m_k.size(), 0);
}

template<x32or64 T>
void _Sha2Impl<T>::finalize() {
    this->pad_md();
    this->append_length();
}

template<x32or64 T>
void _Sha2Impl<T>::process_block() {
    T a = this->m_state.at(0),
        b = this->m_state.at(1),
        c = this->m_state.at(2),
        d = this->m_state.at(3),
        e = this->m_state.at(4),
        f = this->m_state.at(5),
        g = this->m_state.at(6),
        h = this->m_state.at(7),
        s0, s1, tmp1, tmp2;

    unsigned i;

#if(DEBUG)
    this->print_block();

#endif
    for (i = 0; i < m_k.size(); i++) {
        if (i < 16) {
            // Copy words from block into working array
            m_v.at(i) = this->m_block.at(i);
        } else {
            // Expand the 16 first bytes of the working array
            s0 = ror<T>(m_v.at((-15ll) + i), m_rc.at(0)) ^
                 ror<T>(m_v.at((-15ll) + i), m_rc.at(1)) ^
                 (m_v.at((-15ll) + i) >> m_rc.at(2));
            s1 = ror<T>(m_v.at((-2ll) + i), m_rc.at(3)) ^
                 ror<T>(m_v.at((-2ll) + i), m_rc.at(4)) ^
                 (m_v.at((-2ll) + i) >> m_rc.at(5));
            m_v.at(i) = m_v.at((-16ll) + i) + s0 + m_v.at((-7ll) + i) + s1;
        }
    }

    // Compress
    for (i = 0; i < m_k.size(); i++) {
        s0 = ror<T>(a, m_rc.at(6)) ^ ror<T>(a, m_rc.at(7)) ^ ror<T>(a, m_rc.at(8));
        s1 = ror<T>(e, m_rc.at(9)) ^ ror<T>(e, m_rc.at(10)) ^ ror<T>(e, m_rc.at(11));
        tmp1 = h + s1 + ((e & f) ^ (~e & g)) + m_k.at(i) + m_v.at(i);
        tmp2 = s0 + ((a & b) ^ (a & c) ^ (b & c));

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
    this->m_state.at(0) += a;
    this->m_state.at(1) += b;
    this->m_state.at(2) += c;
    this->m_state.at(3) += d;
    this->m_state.at(4) += e;
    this->m_state.at(5) += f;
    this->m_state.at(6) += g;
    this->m_state.at(7) += h;

    this->clear_block();
}

template class _Sha2Impl<uint32_t>;
template class _Sha2Impl<uint64_t>;

SHA224::SHA224() {
    set_digestsize(28);
    reset();
}

void SHA224::init_state() {
    m_state.assign(SHA224_IV.begin(), SHA224_IV.end());
    init_intermediate();
}

SHA256::SHA256() {
    set_digestsize(32);
    reset();
}

void SHA256::init_state() {
    m_state.assign(SHA256_IV.begin(), SHA256_IV.end());
    init_intermediate();
}

SHA384::SHA384() {
    set_digestsize(48);
    reset();
}

void SHA384::init_state() {
    m_state.assign(SHA384_IV.begin(), SHA384_IV.end());
    init_intermediate();
}

SHA512::SHA512() {
    set_digestsize(64);
    reset();
}

void SHA512::init_state() {
    m_state.assign(SHA512_IV.begin(), SHA512_IV.end());
    init_intermediate();
}
