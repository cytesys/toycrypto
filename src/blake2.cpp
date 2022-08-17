#include <array>
#include <iostream>
#include <cmath>

#include "toycrypto.hpp"
#include "common.hpp"

constexpr unsigned int BLOCK_SIZE = 16;
constexpr unsigned int IV_SIZE = 8;
//constexpr std::array<unsigned int, 8> PRIMES = {2, 3, 5, 7, 11, 13, 17, 19};

#define T_BYTES (sizeof(T))
#define T_BITS (T_BYTES * 8)

#define BLOCK_BYTES (BLOCK_SIZE * T_BYTES)

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

constexpr std::array<u32, IV_SIZE> IV32 = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

constexpr std::array<u64, IV_SIZE> IV64 = {
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

template<class T>
class Blake2 {
public:
	Blake2(unsigned int type);
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	// States
	std::array<T, BLOCK_SIZE> m_block = {};
	std::array<T, BLOCK_SIZE> m_v = {};
	std::array<T, IV_SIZE> m_h = {};

	// Constants
	//std::array<T, IV_SIZE> m_iv = {};
	std::array<unsigned int, 4> m_rc = {};

	unsigned int m_hash_length;
	T m_key = 0;

	//void generate_iv();
	void load(std::istream* const input);
	void comp(u64 length, bool is_final);
	void G(unsigned int i, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int y);

	// For debugging purposes
	void print_block() const;
	void print_v() const;
	void print_h() const;
};

// For debugging purposes
template<class T>
void Blake2<T>::print_block() const {
	unsigned int i;
	unsigned int perline = 4;

	if constexpr (std::is_same<T, u64>::value) {
		perline = 2;
	}

	std::cout << "-- BLOCK --" << std::endl;
	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<T>(m_block.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;;
}

// For debugging purposes
template<class T>
void Blake2<T>::print_v() const {
	unsigned int i;
	unsigned int perline = 4;

	if constexpr (std::is_same<T, u64>::value) {
		perline = 2;
	}

	std::cout << "-- V --" << std::endl;
	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<T>(m_v.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;;
}

// For debugging purposes
template<class T>
void Blake2<T>::print_h() const {
	unsigned int i;
	unsigned int perline = 4;

	if constexpr (std::is_same<T, u64>::value) {
		perline = 2;
	}

	std::cout << "-- H --" << std::endl;
	for (i = 0; i < IV_SIZE; i++) {
		std::cout << to_hex<T>(m_h.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;;
}

template<class T>
Blake2<T>::Blake2(unsigned int bitlength) : m_hash_length(bitlength / 8) {
	switch (bitlength) {
		case 128:
			break;
		case 160:
			break;
		case 224:
			break;
		case 256:
			break;
		case 384:
			break;
		case 512:
			break;
		default:
			throw TC::exceptions::NotImplementedError("Blake2: This type is not implemented!");
	}

	// Generate initial values
	/*generate_iv();
	m_h = m_iv;*/

	// Set round constants
	if constexpr (std::is_same<T, u32>::value) {
		// 32-bit
		m_rc = {16, 12, 8, 7};
		m_h = IV32;
	} else if constexpr (std::is_same<T, u64>::value) {
		// 64-bit
		m_rc = {32, 24, 16, 63};
		m_h = IV64;
	} else {
		throw TC::exceptions::TCException("Blake2: The template type is not supported!");
	}
}

//template<class T>
//void Blake2<T>::generate_iv() {
//	// FIXME: This does not work properly, due to insufficient size of double.
//	unsigned int i;
//	std::cout << "-- IV --" << std::endl;
//	for (i = 0; i < IV_SIZE; i++) {
//		double a = std::pow(2, T_BITS);
//		double b = std::sqrt(PRIMES.at(i));
//		double c = b - std::floor(b);
//		//std::cout << "A = " << a << ", B = " << b << ", C = " << c << std::endl;
//		m_iv.at(i) = std::floor(a * c);
//
//		// Debug
//		std::cout << to_hex<T>(m_iv.at(i)) << " ";
//		if ((i + 1) % 2 == 0) {
//			std::cout << std::endl;
//		} else {
//			std::cout << "- ";
//		}
//	
//	}
//	std::cout << "---" << std::endl << std::endl;;
//}

template<class T>
auto Blake2<T>::hexdigest(std::istream* const input) -> std::string* const {
	// Set parameters
	m_h.at(0) ^= 0x01010000 ^ (m_key << 8) ^ (T)(m_hash_length / 8);

	// Load input
	load(input);

	// Generate output
	static std::string out = "";
	unsigned int i;

	for (i = 0; i < (m_hash_length / T_BITS); i++) {
		out += to_hex<T>(m_h.at(i), true);
	}

	return &out;
}

template<class T>
void Blake2<T>::load(std::istream* const input) {
	char* buffer = new char[BLOCK_BYTES];
	size_t read = 0;
	u64 length = 0;
	unsigned int i;

	// Load input
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Blake2: Could not read the input!");
		}

		input->read(buffer, BLOCK_BYTES);
		read = input->gcount();
		length += read;

		for (i = 0; i < (read / T_BYTES); i++) {
			m_block.at(i) = load_le<T>(buffer, BLOCK_BYTES, i * T_BYTES);
		}

		// Load the rest of the bytes
		if ((read % T_BYTES) > 0) {
			m_block.at(i) = load_le<T>(buffer, BLOCK_BYTES, i * T_BYTES, read % T_BYTES);
		}

		// Process the block if it's big enough
		if (read == BLOCK_BYTES) {
			if (input->peek() == EOF) {
				comp(length, true);
			} else {
				comp(length, false);
			}
			read = 0;
		}
	}

	delete[] buffer;

	if (read > 0) {
		comp(length, true);
	}
}

template<class T>
void Blake2<T>::comp(u64 length, bool is_final) {
	// For debugging
	//print_block();

	unsigned int i;
	unsigned int r = 10;

	if constexpr (std::is_same<T, u64>::value) {
		r = 12;
	}

	// Initialize local work vector
	for (i = 0; i < IV_SIZE; i++) {
		m_v.at(i) = m_h.at(i);
		if constexpr (std::is_same<T, u32>::value) {
			// 32-bit
			m_v.at(IV_SIZE + i) = IV32.at(i);
		} else {
			// 64-bit
			m_v.at(IV_SIZE + i) = IV64.at(i);
		}
	}

	m_v.at(12) ^= (T)(length);
	if constexpr (std::is_same<T, u32>::value) {
		// 32-bit
		m_v.at(13) ^= (u32)(length >> 32);
	}

	if (is_final) {
		m_v.at(14) = ~m_v.at(14);
	}
	// For debugging
	//print_v();

	// Cryptographic mixing
	for (i = 0; i < r; i++) {
		G(i, 0, 4, 8, 12, 0, 1);
		G(i, 1, 5, 9, 13, 2, 3);
		G(i, 2, 6, 10, 14, 4, 5);
		G(i, 3, 7, 11, 15, 6, 7);

		G(i, 0, 5, 10, 15, 8, 9);
		G(i, 1, 6, 11, 12, 10, 11);
		G(i, 2, 7, 8, 13, 12, 13);
		G(i, 3, 4, 9, 14, 14, 15);

		// For debugging
		//print_v();
	}

	for (i = 0; i < IV_SIZE; i++) {
		m_h.at(i) ^= m_v.at(i) ^ m_v.at(IV_SIZE + i);
	}

	// For debugging
	//print_h();

	// Empty m_block
	m_block.fill(0);
}

template<class T>
void Blake2<T>::G(unsigned int i, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int y) {
	T va = m_v.at(a);
	T vb = m_v.at(b);
	T vc = m_v.at(c);
	T vd = m_v.at(d);

	T xx = m_block.at(SIGMA.at(i % 10).at(x));
	T yy = m_block.at(SIGMA.at(i % 10).at(y));

	va += vb + xx;
	vd = rotateright<T>(vd ^ va, m_rc.at(0));
	vc += vd;
	vb = rotateright<T>(vb ^ vc, m_rc.at(1));
	va += vb + yy;
	vd = rotateright<T>(vd ^ va, m_rc.at(2));
	vc += vd;
	vb = rotateright<T>(vb ^ vc, m_rc.at(3));

	m_v.at(a) = va;
	m_v.at(b) = vb;
	m_v.at(c) = vc;
	m_v.at(d) = vd;
}

auto TC::BLAKE::blake2s(unsigned int bitlength, std::istream* const input) -> std::string* const {
	Blake2<u32> inst(bitlength);
	return inst.hexdigest(input);
}

auto TC::BLAKE::blake2b(unsigned int bitlength, std::istream* const input) -> std::string* const {
	Blake2<u64> inst(bitlength);
	return inst.hexdigest(input);
}
