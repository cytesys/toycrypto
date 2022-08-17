#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

constexpr unsigned int BLOCK_SIZE = 16;
constexpr unsigned int BLOCK_BYTES = BLOCK_SIZE * 4;

constexpr unsigned int K_SIZE = 64;
constexpr std::array<u32, K_SIZE> K = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constexpr unsigned int S_SIZE = 64;
constexpr std::array<unsigned int, S_SIZE> S = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

constexpr unsigned int H_SIZE = 4;
constexpr std::array<u32, H_SIZE> IV = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

class MD5 {
public:
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	std::array<u32, BLOCK_SIZE> m_block = {};
	std::array<u32, H_SIZE> m_h = IV;

	void load(std::istream* const input);
	void comp();

	// For debugging purposes
	void print_block() const;
};

// For debugging purposes
void MD5::print_block() const {
	unsigned int i;

	std::cout << "-- BLOCK --" << std::endl;
	for (i = 0; i < m_block.size(); i++) {
		std::cout << to_hex<u32>(m_block.at(i)) << " ";
		if ((i + 1) % 4 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << "---" << std::endl << std::endl;
}

auto MD5::hexdigest(std::istream* const input) -> std::string* const {
	// Load input
	load(input);

	// Generate output
	static std::string result = "";
	for (u32 i : m_h) {
		result += to_hex<u32>(i, true);
	}
	return &result;
}

void MD5::load(std::istream* const input) {
	char* buffer = new char[BLOCK_BYTES]; 
	u64 length = 0;
	u64 read = 0;
	unsigned int i;

	// Read the whole stream while processing it
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("MD5: Could not read the input!");
		}

		input->read(buffer, BLOCK_BYTES);
		read = input->gcount();
		length += read * 8;

		for (i = 0; i < (read / 4); i++) {
			m_block.at(i) = load_le<u32>(buffer, BLOCK_BYTES, i * 4);
		}

		// Read the rest of the bytes
		if ((read % 4) > 0) {
			m_block.at(i) = load_le<u32>(buffer, BLOCK_BYTES, i * 4, read % 4);
		}

		if (read == BLOCK_BYTES) {
			comp();
			read = 0;
		}
	}

	delete[] buffer;

	// Append the padding byte
	m_block.at(read / 4) ^= xor_mask_le<u32>(0x80, read);

	// Process the block if the message length don't fit
	if (read + 8 >= BLOCK_BYTES) {
		comp();
	}

	// Append the message length
	m_block.at(BLOCK_SIZE - 2) = length & U32MAX;
	m_block.at(BLOCK_SIZE - 1) = (length >> 32) & U32MAX;

	comp();
}

void MD5::comp() {
	// For debugging purposes
	//print_block();

	unsigned int i;

	u32 a = m_h.at(0);
	u32 b = m_h.at(1);
	u32 c = m_h.at(2);
	u32 d = m_h.at(3);

	for (i = 0; i < BLOCK_BYTES; i++) {
		u32 f, g;
		if (i >=0 && i <=15) {
			f = (b & c) | ((~b) & d);
			g = i;
		} else if (i >= 16 && i <= 31) {
			f = (d & b) | ((~d) & c);
			g = ((5 * i) + 1) % 16;
		} else if (i >= 32 && i <= 47) {
			f = b ^ c ^ d;
			g = ((3 * i) + 5) % 16;
		} else {
			f = c ^ (b | (~d));
			g = (7 * i) % 16;
		}

		f = f + a + K.at(i) + m_block.at(g);
		a = d;
		d = c;
		c = b;
		b = b + rotateleft<u32>(f, S.at(i));
	}

	m_h.at(0) += a;
	m_h.at(1) += b;
	m_h.at(2) += c;
	m_h.at(3) += d;

	// Clear m_block
	m_block.fill(0);
}

auto TC::MD::md5(std::istream* const input) -> std::string* const {
	MD5 inst = MD5();
	return inst.hexdigest(input);
}