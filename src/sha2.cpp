#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

#define T_BYTES sizeof(T)
#define T_BITS (T_BYTES * 8)

#define BLOCK_SIZE 16
#define BLOCK_BYTES (BLOCK_SIZE * T_BYTES)

// Constant values for H
#define H_SIZE 8
constexpr std::array<u32, H_SIZE> H_SHA224 = {
	0xc1059ed8, 0x367cd507,
	0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511,
	0x64f98fa7, 0xbefa4fa4
};
constexpr std::array<u32, H_SIZE> H_SHA256 = {
	0x6a09e667, 0xbb67ae85,
	0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19
};
constexpr std::array<u64, H_SIZE> H_SHA384 = {
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
	0x9159015a3070dd17, 0x152fecd8f70e5939,
	0x67332667ffc00b31, 0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};
constexpr std::array<u64, H_SIZE> H_SHA512 = {
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// TODO: Generate these tables automatically for different subtypes
constexpr std::array<u64, H_SIZE> H_SHA512_224 = {
	0x8c3d37c819544da2, 0x73e1996689dcd4d6,
	0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
	0x0f6d2b697bd44da8, 0x77e36f7304c48942,
	0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
};
constexpr std::array<u64, H_SIZE> H_SHA512_256 = {
	0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
	0x2393b86b6f53b151, 0x963877195940eabd,
	0x96283ee2a88effe3, 0xbe5e1e2553863992,
	0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
};

// Constants for K
#define K32_SIZE 64
#define K64_SIZE 80

#define K_SIZE ((std::is_same<T, u64>::value) ? K64_SIZE : K32_SIZE)

constexpr std::array<u32, K32_SIZE> K32 = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe,	0x9bdc06a7,	0xc19bf174,
	0xe49b69c1,	0xefbe4786,	0x0fc19dc6,	0x240ca1cc,
	0x2de92c6f,	0x4a7484aa,	0x5cb0a9dc,	0x76f988da,
	0x983e5152,	0xa831c66d,	0xb00327c8,	0xbf597fc7,
	0xc6e00bf3,	0xd5a79147,	0x06ca6351,	0x14292967,
	0x27b70a85,	0x2e1b2138,	0x4d2c6dfc,	0x53380d13,
	0x650a7354,	0x766a0abb,	0x81c2c92e,	0x92722c85,
	0xa2bfe8a1,	0xa81a664b,	0xc24b8b70,	0xc76c51a3,
	0xd192e819,	0xd6990624,	0xf40e3585,	0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
constexpr std::array<u64, K64_SIZE> K64 = {
	0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019,
	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926,
	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001,
	0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910,
	0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60,
	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207,
	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

template<class T>
class SHA2 {
public:
	SHA2(unsigned int type, unsigned int subtype = 0);
	auto hexdigest(std::istream* const input) -> std::string* const;

private:
	std::array<T, H_SIZE> m_h = {};
	std::array<T, BLOCK_SIZE> m_block = {};

	unsigned int m_type;
	unsigned int m_subtype;

	void load(std::istream* const input);
	void comp();

	// For debugging
	void print_block() const;
};

template<class T>
SHA2<T>::SHA2(unsigned int type, unsigned int subtype) : m_type(type), m_subtype(subtype) {
	if constexpr (std::is_same<T, u64>::value) {
		// 64-bit
		if (type == 512) {
			switch (subtype) {
				case 0:
					m_h = H_SHA512;
					break;
				case 224:
					m_h = H_SHA512_224;
					break;
				case 256:
					m_h = H_SHA512_256;
					break;
				case 512:
					m_h = H_SHA512;
					break;
				default:
					throw TC::exceptions::NotImplementedError("The subtype for SHA512 is not implemented!");
			}
		} else if (type == 384) {
			m_h = H_SHA384;
		} else {
			throw TC::exceptions::NotImplementedError("The (64-bit) SHA2 type is not implemented!");
		}
	} else if constexpr (std::is_same<T, u32>::value) {
		// 32-bit
		switch (type) {
			case 224:
				m_h = H_SHA224;
				break;
			case 256:
				m_h = H_SHA256;
				break;
			default:
				throw TC::exceptions::NotImplementedError("The (32-bit) SHA2 type is not implemented!");
		}
	} else {
		throw TC::exceptions::TCException("The template type for SHA2 is invalid!");
	}
}

// For debugging purposes
template<class T>
void SHA2<T>::print_block() const {
	unsigned int i;
	unsigned int perline = 4;

	if constexpr (std::is_same<T, u64>::value) {
		perline = 2;
	}

	for (i = 0; i < BLOCK_SIZE; i++) {
		std::cout << to_hex<T>(m_block.at(i)) << " ";
		if ((i + 1) % perline == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl;
}

template<class T>
auto SHA2<T>::hexdigest(std::istream* const input) -> std::string* const {
	load(input);

	static std::string result = "";
	unsigned int i;

	for (i = 0; i < (m_type / T_BITS); i++) {
		result += to_hex<T>(m_h.at(i));
	}

	return &result;
}

template<class T>
void SHA2<T>::load(std::istream* const input) {
	u64 length = 0;
	size_t read = 0;
	unsigned int i;
	char* buffer = new char[BLOCK_BYTES] {};

	// Read the entire file
	while (input->peek() != EOF) {
		read = input->readsome(buffer, BLOCK_BYTES);
		length += read * 8;

		// Read in whole parts
		for (i = 0; i < (read / T_BYTES); i++) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES);
		}

		// Read in the rest
		if ((read % T_BYTES) > 0) {
			m_block.at(i) = load_be<T>(buffer, BLOCK_BYTES, i * T_BYTES, read % T_BYTES);
		}

		if (read == BLOCK_BYTES) {
			comp();
			read = 0;
		}
	}

	delete[] buffer;

	// Apply padding
	m_block.at(read / T_BYTES) ^= xor_mask_be<T>(0x80, read % T_BYTES);

	// In case the message length does not fit
	if (read + (T_BYTES * 2) >= BLOCK_BYTES) {
		comp();
	}

	// Append message length
	if constexpr(std::is_same<T, u64>::value) {
		// 64-bit
		m_block.at(BLOCK_SIZE - 1) = length;
	} else if constexpr(std::is_same<T, u32>::value) {
		// 32-bit
		m_block.at(BLOCK_SIZE - 2) = (length >> 32) & U32MAX;
		m_block.at(BLOCK_SIZE - 1) = length & U32MAX;
	} else {
		throw TC::exceptions::TCException("The template type for SHA2 is invalid!");
	}

	comp();
}

template<class T>
void SHA2<T>::comp() {
	// For debugging
	//print_block();

	std::array<T, K_SIZE> words = {};
	size_t j;

	// Copy chunk into the 16 first words
	for (j = 0; j < BLOCK_SIZE; j++) {
		words.at(j) = m_block.at(j);
	}

	// Clear m_chunk
	m_block.fill(0);

	// Extend the first 16 words to the remaining 48
	for (j = BLOCK_SIZE; j < K_SIZE; j++) {
		T s0, s1;
		if constexpr(std::is_same<T, u64>::value) {
			// 64-bit
			s0 = rotateright<T>(words.at(j - 15), 1) ^ rotateright<T>(words.at(j - 15), 8) ^ (words.at(j - 15) >> 7);
			s1 = rotateright<T>(words.at(j - 2), 19) ^ rotateright<T>(words.at(j - 2), 61) ^ (words.at(j - 2) >> 6);
		} else if constexpr(std::is_same<T, u32>::value) {
			// 32-bit
			s0 = rotateright<T>(words.at(j - 15), 7) ^ rotateright<T>(words.at(j - 15), 18) ^ (words.at(j - 15) >> 3);
			s1 = rotateright<T>(words.at(j - 2), 17) ^ rotateright<T>(words.at(j - 2), 19) ^ (words.at(j - 2) >> 10);
		} else {
			throw TC::exceptions::TCException("The template type for SHA2 is invalid!");
		}
		words.at(j) = words.at(j - 16) + s0 + words.at(j - 7) + s1;
	}

	T a = m_h.at(0);
	T b = m_h.at(1);
	T c = m_h.at(2);
	T d = m_h.at(3);
	T e = m_h.at(4);
	T f = m_h.at(5);
	T g = m_h.at(6);
	T h = m_h.at(7);

	// Main compression loop
	for (j = 0; j < K_SIZE; j++) {
		T temp1, temp2;
		if constexpr(std::is_same<T, u64>::value) {
			// 64-bit
			T s0 = rotateright<T>(a, 28) ^ rotateright<T>(a, 34) ^ rotateright<T>(a, 39);
			T s1 = rotateright<T>(e, 14) ^ rotateright<T>(e, 18) ^ rotateright<T>(e, 41);
			T ch = (e & f) ^ (~e & g);
			temp1 = h + s1 + ch + K64.at(j) + words.at(j);
			T maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 + maj;
		} else if constexpr(std::is_same<T, u32>::value) {
			// 32-bit
			T s0 = rotateright<T>(a, 2) ^ rotateright<T>(a, 13) ^ rotateright<T>(a, 22);
			T s1 = rotateright<T>(e, 6) ^ rotateright<T>(e, 11) ^ rotateright<T>(e, 25);
			T ch = (e & f) ^ (~e & g);
			temp1 = h + s1 + ch + K32.at(j) + words.at(j);
			T maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 + maj;
		} else {
			throw TC::exceptions::TCException("The template type for SHA2 is invalid!");
		}

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

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
}

// A class for the "32-bit" version of SHA2
//class SHA2_32 {
//public:
//	explicit SHA2_32(int type);
//	void load(std::istream* infile);
//	auto output() const -> str;
//
//private:
//	std::array<u32, H_SIZE> m_h = {};
//	std::array<u32, K32_SIZE> m_k = K32;
//	std::array<u32, CHUNK_SIZE> m_chunk = {};
//	int m_type;
//
//	void handle();
//};
//
//SHA2_32::SHA2_32(int type)
//{
//	switch(type) {
//		case 224:
//			m_h = H_SHA224;
//			break;
//		case 256:
//			m_h = H_SHA256;
//			break;
//		default:
//			throw TC::exceptions::NotImplementedError("The SHA2 type supplied is not implemented.");
//			break;
//	}
//
//	m_type = type;
//}
//
//void SHA2_32::load(std::istream* infile)
//{
//	u64 length = 0;
//	int index = 0;
//	char* buffer = new char[CHUNK32_BYTES] {};
//
//	// Read the entire file
//	while (infile->peek() != EOF) {
//		index = infile->readsome(buffer, CHUNK32_BYTES);
//		length += index * 8;
//
//		// Read in whole dwords
//		int i;
//		for (i = 0; i < (index / 4); i++) {
//			m_chunk.at(i) = load_be<u32>(buffer, CHUNK32_BYTES, i * 4);
//		}
//
//		// Read in the rest
//		if ((index % 4) > 0) {
//			m_chunk.at(i) = load_be<u32>(buffer, CHUNK32_BYTES, i * 4, index % 4);
//		}
//
//		if (index == CHUNK32_BYTES) {
//			handle();
//			index = 0;
//		}
//	}
//
//	delete[] buffer;
//
//	// Apply padding
//	m_chunk.at(index / 4) ^= xor_mask_be<u32>(PADDING_BYTE, index % 4);
//	index++;
//
//	// In case the message length does not fit
//	if (index + 8 >= CHUNK32_BYTES) {
//		handle();
//	}
//
//	// Append message length
//	m_chunk.at(CHUNK_SIZE - 2) = (length >> 32) & U32MAX;
//	m_chunk.at(CHUNK_SIZE - 1) = length & U32MAX;
//	handle();
//}
//
//void SHA2_32::handle()
//{
//	std::array<u32, K32_SIZE> words = {};
//
//	// Copy chunk into the 16 first words
//	for (u64 j = 0; j < CHUNK_SIZE; j++) {
//		words.at(j) = m_chunk.at(j);
//	}
//
//	// Clear m_chunk
//	m_chunk.fill(0);
//
//	// Extend the first 16 words to the remaining 48
//	for (u64 j = CHUNK_SIZE; j < K32_SIZE; j++) {
//		u32 s0 = rotateright<u32>(words.at(j - 15), 7) ^ rotateright<u32>(words.at(j - 15), 18) ^ (words.at(j - 15) >> 3);
//		u32 s1 = rotateright<u32>(words.at(j - 2), 17) ^ rotateright<u32>(words.at(j - 2), 19) ^ (words.at(j - 2) >> 10);
//		words.at(j) = words.at(j - 16) + s0 + words.at(j - 7) + s1;
//	}
//
//	u32 a = m_h.at(0);
//	u32 b = m_h.at(1);
//	u32 c = m_h.at(2);
//	u32 d = m_h.at(3);
//	u32 e = m_h.at(4);
//	u32 f = m_h.at(5);
//	u32 g = m_h.at(6);
//	u32 h = m_h.at(7);
//
//	// Main compression loop
//	for (int j = 0; j < K32_SIZE; j++) {
//		u32 s1 = rotateright<u32>(e, 6) ^ rotateright<u32>(e, 11) ^ rotateright<u32>(e, 25);
//		u32 ch = (e & f) ^ (~e & g);
//		u32 temp1 = h + s1 + ch + m_k.at(j) + words.at(j);
//		u32 s0 = rotateright<u32>(a, 2) ^ rotateright<u32>(a, 13) ^ rotateright<u32>(a, 22);
//		u32 maj = (a & b) ^ (a & c) ^ (b & c);
//		u32 temp2 = s0 + maj;
//
//		h = g;
//		g = f;
//		f = e;
//		e = d + temp1;
//		d = c;
//		c = b;
//		b = a;
//		a = temp1 + temp2;
//
//	}
//
//	// Add the compressed chunk to the current hash value
//	m_h.at(0) += a;
//	m_h.at(1) += b;
//	m_h.at(2) += c;
//	m_h.at(3) += d;
//	m_h.at(4) += e;
//	m_h.at(5) += f;
//	m_h.at(6) += g;
//	m_h.at(7) += h;
//}
//
//auto SHA2_32::output() const -> str
//{
//	str result = "";
//
//	for (int i = 0; i < (m_type / 32); i++) {
//		result += to_hex<u32>(m_h.at(i));
//	}
//
//	return result;
//}
//
//// A class for the "64-bit" version of SHA2
//class SHA2_64 {
//public:
//	explicit SHA2_64(int type, int subtype);
//	void load(std::istream* infile);
//	auto output() const -> str;
//
//private:
//	std::array<u64, H_SIZE> m_h{ {} };
//	std::array<u64, K64_SIZE> m_k = K64;
//	std::array<u64, CHUNK_SIZE> m_chunk{ {} };
//	int m_type;
//	int m_subtype;
//
//	void handle();
//
//	// For debugging
//	void print_chunk() const;
//	void print_h() const;
//};
//
//SHA2_64::SHA2_64(int type, int subtype)
//{
//	switch(type) {
//		case 384:
//			m_h = H_SHA384;
//			break;
//		case 512:
//			switch(subtype) {
//				case 0:
//					m_h = H_SHA512;
//					break;
//				case 224:
//					m_h = H_SHA512_224;
//					break;
//				case 256:
//					m_h = H_SHA512_256;
//					break;
//				default:
//					throw TC::exceptions::NotImplementedError("The SHA2 subtype supplied is not implemented");
//			}
//			break;
//		default:
//			throw TC::exceptions::NotImplementedError("The SHA2 type supplied is invalid or not implemented");
//			break;
//	}
//
//	m_type = type;
//	m_subtype = subtype;
//}
//
//// For debugging
//void SHA2_64::print_chunk() const {
//	std::cout << "-- C --" << std::endl;
//	for (int i = 0; i < m_chunk.size(); i++) {
//		std::cout << to_hex<u64>(m_chunk[i]) << " ";
//		if ((i + 1) % 2 == 0) {
//			std::cout << std::endl;
//		} else {
//			std::cout << "- ";
//		}
//	}
//	std::cout << "-------" << std::endl << std::endl;
//}
//
//// For debugging
//void SHA2_64::print_h() const {
//	std::cout << "-- H --" << std::endl;
//	for (int i = 0; i < m_h.size(); i++) {
//		std::cout << to_hex<u64>(m_h[i]) << " ";
//		if ((i + 1) % 2 == 0) {
//			std::cout << std::endl;
//		} else {
//			std::cout << "- ";
//		}
//	}
//	std::cout << "-------" << std::endl << std::endl;
//}
//
//void SHA2_64::load(std::istream* infile) {
//	u64 length = 0;
//	int index = 0;
//	char* buffer = new char[CHUNK64_BYTES];
//
//	// Read the entire file
//	while (infile->peek() != EOF) {
//		index = infile->readsome(buffer, CHUNK64_BYTES);
//		length += index * 8;
//
//		// Read in whole 64-bit qwords
//		int i;
//		for (i = 0; i < (index / 8); i++) {
//			m_chunk.at(i) = load_be<u64>(buffer, CHUNK64_BYTES, i * 8);
//		}
//
//		// Read in the rest
//		if ((index % 8) > 0) {
//			m_chunk.at(i) = load_be<u64>(buffer, CHUNK64_BYTES, i * 8, index % 8);
//		}
//
//		if (index == CHUNK64_BYTES) {
//			handle();
//			index = 0;
//		}
//	}
//
//	delete[] buffer;
//
//	// Apply padding
//	m_chunk.at(index / 8) ^= xor_mask_be<u64>(PADDING_BYTE, index % 8);
//	index++;
//
//	// In case the message length does not fit
//	if (index + 8 >= CHUNK64_BYTES) {
//		handle();
//	}
//
//	// Append message length
//	m_chunk.at(CHUNK_SIZE - 1) = length;
//	handle();
//}
//
//void SHA2_64::handle()
//{
//	//print_chunk();
//	std::array<u64, K64_SIZE> words = {};
//
//	// Copy chunk into the 16 first words
//	for (int j = 0; j < CHUNK_SIZE; j++) {
//		words.at(j) = m_chunk.at(j);
//	}
//
//	// Clear m_chunk
//	m_chunk.fill(0);
//
//	// Extend the first 16 words to 80
//	for (int j = 16; j < K64_SIZE; j++) {
//		u64 s0 = rotateright<u64>(words.at(j - 15), 1) ^ rotateright<u64>(words.at(j - 15), 8) ^ (words.at(j - 15) >> 7);
//		u64 s1 = rotateright<u64>(words.at(j - 2), 19) ^ rotateright<u64>(words.at(j - 2), 61) ^ (words.at(j - 2) >> 6);
//		words.at(j) = words.at(j - 16) + s0 + words.at(j - 7) + s1;
//	}
//
//	u64 a = m_h.at(0);
//	u64 b = m_h.at(1);
//	u64 c = m_h.at(2);
//	u64 d = m_h.at(3);
//	u64 e = m_h.at(4);
//	u64 f = m_h.at(5);
//	u64 g = m_h.at(6);
//	u64 h = m_h.at(7);
//
//	// Main compression loop
//	for (int j = 0; j < K64_SIZE; j++) {
//		u64 s1 = rotateright<u64>(e, 14) ^ rotateright<u64>(e, 18) ^ rotateright<u64>(e, 41);
//		u64 ch = (e & f) ^ (~e & g);
//		u64 temp1 = h + s1 + ch + m_k.at(j) + words.at(j);
//		u64 s0 = rotateright<u64>(a, 28) ^ rotateright<u64>(a, 34) ^ rotateright<u64>(a, 39);
//		u64 maj = (a & b) ^ (a & c) ^ (b & c);
//		u64 temp2 = s0 + maj;
//
//		h = g;
//		g = f;
//		f = e;
//		e = d + temp1;
//		d = c;
//		c = b;
//		b = a;
//		a = temp1 + temp2;
//
//	}
//
//	// Add the compressed chunk to the current hash value
//	m_h.at(0) += a;
//	m_h.at(1) += b;
//	m_h.at(2) += c;
//	m_h.at(3) += d;
//	m_h.at(4) += e;
//	m_h.at(5) += f;
//	m_h.at(6) += g;
//	m_h.at(7) += h;
//}
//
//auto SHA2_64::output() const -> str
//{
//	str result = "";
//	unsigned int length = m_subtype;
//	unsigned int i;
//
//	if (length == 0)
//		length = m_type;
//
//	// Whole qwords
//	for (i = 0; i < (length / 64); i++) {
//		result += to_hex<u64>(m_h.at(i));
//	}
//
//	// The rest
//	if ((length % 64) > 0) {
//		for (i = 0; i < (length % 64); i++) {
//			result += to_hex<u8>((m_h.at(i) >> (i * 8)) & 0xff);
//		}
//	}
//
//	return result;
//}

auto TC::SHA::sha224(std::istream* input) -> std::string* const {
	SHA2<u32> inst(224);
	return inst.hexdigest(input);
}

auto TC::SHA::sha256(std::istream* input) -> std::string* const {
	SHA2<u32> inst(256);
	return inst.hexdigest(input);
}

auto TC::SHA::sha384(std::istream* input) -> std::string* const {
	SHA2<u64> inst(384);
	return inst.hexdigest(input);
}

auto TC::SHA::sha512(std::istream* input, unsigned int subtype) -> std::string* const {
	SHA2<u64> inst(512, subtype);
	return inst.hexdigest(input);
}

//auto TC::SHA::sha224(std::istream* input) -> str
//{
//	SHA2_32 inst(224);
//	inst.load(input);
//	return inst.output();
//}
//
//auto TC::SHA::sha256(std::istream* input) -> str
//{
//	SHA2_32 inst(256);
//	inst.load(input);
//	return inst.output();
//}
//
//auto TC::SHA::sha384(std::istream* input) -> str
//{
//	SHA2_64 inst(384, 0);
//	inst.load(input);
//	return inst.output();
//}
//
//auto TC::SHA::sha512(std::istream* input, int subtype) -> str
//{
//	SHA2_64 inst(512, subtype);
//	inst.load(input);
//	return inst.output();
//}
