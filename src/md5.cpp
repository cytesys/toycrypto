#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

#define CHUNK_SIZE 16
#define CHUNK_BYTES 64
#define PADDING_BYTE 0x80

constexpr std::array<u32, 64> K = {
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

constexpr std::array<unsigned int, 64> S = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

class MD5 {
public:
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	std::array<u32, CHUNK_SIZE> m_x{ {} };
	u32 m_a = 0x67452301;
	u32 m_b = 0xefcdab89;
	u32 m_c = 0x98badcfe;
	u32 m_d = 0x10325476;

	void load(std::istream* const input);
	void handle();

	// For debugging purposes
	void print_x() const;
};

// For debugging purposes
void MD5::print_x() const {
	unsigned int i;
	for (i = 0; i < m_x.size(); i++) {
		std::cout << to_hex<u32>(m_x.at(i)) << " ";
		if ((i + 1) % 4 == 0) {
			std::cout << std::endl;
		} else {
			std::cout << "- ";
		}
	}
	std::cout << std::endl;
}

auto MD5::hexdigest(std::istream* const input) -> std::string* const {
	load(input);

	static str result = "";
	result += to_hex<u32>(m_a, true);
	result += to_hex<u32>(m_b, true);
	result += to_hex<u32>(m_c, true);
	result += to_hex<u32>(m_d, true);
	return &result;
}

void MD5::load(std::istream* const input) {
	u64 length = 0;
	size_t read = 0;
	unsigned int i;
	char* buffer = new char[CHUNK_BYTES];

	// Read in the data in chunks
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Could not read data!");
		}

		read = input->readsome(buffer, CHUNK_BYTES);
		length += read * 8;

		// Read in whole dwords
		for (i = 0; i < (read / 4); i++) {
			m_x.at(i) = load_le<u32>(buffer, CHUNK_BYTES, i * 4);
		}

		// Read in the rest
		if ((read % 4) > 0) {
			m_x.at(i) = load_le<u32>(buffer, CHUNK_BYTES, i * 4, read % 4);
		}

		if (read == CHUNK_BYTES) {
			handle();
			read = 0;
		}
	}

	delete[] buffer;

	// Add the padding byte
	m_x.at(read / 4) ^= xor_mask_le<u32>(PADDING_BYTE, read);

	// Make a new block if the length don't fit
	if (read + 8 >= CHUNK_BYTES) {
		handle();
	}

	// Append the message length
	m_x.at(CHUNK_SIZE - 2) = length & U32MAX;
	m_x.at(CHUNK_SIZE - 1) = (length >> 32) & U32MAX;

	handle();
}

void MD5::handle() {
	//print_x();
	unsigned int i;

	u32 a = m_a;
	u32 b = m_b;
	u32 c = m_c;
	u32 d = m_d;

	for (i = 0; i < 64; i++) {
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

		f = f + a + K[i] + m_x[g];
		a = d;
		d = c;
		c = b;
		b = b + rotateleft<u32>(f, S[i]);
	}

	m_a += a;
	m_b += b;
	m_c += c;
	m_d += d;

	m_x.fill(0);
}

auto TC::MD::md5(std::istream* const input) -> std::string* const {
	MD5 inst = MD5();
	return inst.hexdigest(input);
}