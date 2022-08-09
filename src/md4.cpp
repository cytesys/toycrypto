#include <array>
#include <cmath>
#include <fstream>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

#define CHUNK_SIZE 64
#define PADDING_BYTE 0x80

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define FF(a, b, c, d, x, s) (rotateleft<u32>((a) + F((b), (c), (d)) + (x), (s)))
#define GG(a, b, c, d, x, s) (rotateleft<u32>((a) + G((b), (c), (d)) + (x) + (u32)0x5a827999, (s)))
#define HH(a, b, c, d, x, s) (rotateleft<u32>((a) + H((b), (c), (d)) + (x) + (u32)0x6ed9eba1, (s)))

class MD4 {
public:
	auto hexdigest(std::istream* const input)->std::string* const;

private:
	std::array<u32, 16> m_x{ {} };
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
void MD4::print_x() const {
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

auto MD4::hexdigest(std::istream* const input) -> std::string* const {
	load(input);

	static std::string result = "";
	result += to_hex<u32>(m_a, true);
	result += to_hex<u32>(m_b, true);
	result += to_hex<u32>(m_c, true);
	result += to_hex<u32>(m_d, true);
	return &result;
}

void MD4::load(std::istream* const input) {
	u64 length = 0;
	size_t read = 0;
	unsigned int i;
	char* buffer = new char[CHUNK_SIZE];

	// Read in the data in chunks
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("Could not read data!");
		}

		read = input->readsome(buffer, CHUNK_SIZE);
		length += read * 8;

		// Read in whole 32-bit words
		for (i = 0; i < (read / 4); i++) {
			//std::cout << "Loading in whole: i = " << i << ", read = " << read << std::endl;
			m_x.at(i) = load_le<u32>(buffer, CHUNK_SIZE, i * 4);
		}

		// Read in the rest
		if ((read % 4) > 0) {
			//std::cout << "Loading in the rest: i = " << i << ", rest = " << read % 4 << std::endl;
			m_x.at(i) = load_le<u32>(buffer, CHUNK_SIZE, i * 4, read % 4);
		}

		if (read == CHUNK_SIZE) {
			handle();
			read = 0;
		}
	}

	delete[] buffer;

	// Add the padding byte
	m_x.at(read / 4) ^= (u32)(PADDING_BYTE) << ((read % 4) * 8);
	read++;

	// Make a new block if the length don't fit
	if (read + 8 >= CHUNK_SIZE) {
		handle();
	}

	// Append the message length
	m_x.at((CHUNK_SIZE / 4) - 2) = length & U32MAX;
	m_x.at((CHUNK_SIZE / 4) - 1) = rotateleft<u64>(length, 32) & U32MAX;

	handle();
}

void MD4::handle()
{
	//print_x();

	u32 a = m_a;
	u32 b = m_b;
	u32 c = m_c;
	u32 d = m_d;

	// Round 1
	a = FF(a, b, c, d, m_x[0], 3);
	d = FF(d, a, b, c, m_x[1], 7);
	c = FF(c, d, a, b, m_x[2], 11);
	b = FF(b, c, d, a, m_x[3], 19);
	a = FF(a, b, c, d, m_x[4], 3);
	d = FF(d, a, b, c, m_x[5], 7);
	c = FF(c, d, a, b, m_x[6], 11);
	b = FF(b, c, d, a, m_x[7], 19);
	a = FF(a, b, c, d, m_x[8], 3);
	d = FF(d, a, b, c, m_x[9], 7);
	c = FF(c, d, a, b, m_x[10], 11);
	b = FF(b, c, d, a, m_x[11], 19);
	a = FF(a, b, c, d, m_x[12], 3);
	d = FF(d, a, b, c, m_x[13], 7);
	c = FF(c, d, a, b, m_x[14], 11);
	b = FF(b, c, d, a, m_x[15], 19);

	// Round 2
	a = GG(a, b, c, d, m_x[0], 3);
	d = GG(d, a, b, c, m_x[4], 5);
	c = GG(c, d, a, b, m_x[8], 9);
	b = GG(b, c, d, a, m_x[12], 13);
	a = GG(a, b, c, d, m_x[1], 3);
	d = GG(d, a, b, c, m_x[5], 5);
	c = GG(c, d, a, b, m_x[9], 9);
	b = GG(b, c, d, a, m_x[13], 13);
	a = GG(a, b, c, d, m_x[2], 3);
	d = GG(d, a, b, c, m_x[6], 5);
	c = GG(c, d, a, b, m_x[10], 9);
	b = GG(b, c, d, a, m_x[14], 13);
	a = GG(a, b, c, d, m_x[3], 3);
	d = GG(d, a, b, c, m_x[7], 5);
	c = GG(c, d, a, b, m_x[11], 9);
	b = GG(b, c, d, a, m_x[15], 13);

	// Round 3
	a = HH(a, b, c, d, m_x[0], 3);
	d = HH(d, a, b, c, m_x[8], 9);
	c = HH(c, d, a, b, m_x[4], 11);
	b = HH(b, c, d, a, m_x[12], 15);
	a = HH(a, b, c, d, m_x[2], 3);
	d = HH(d, a, b, c, m_x[10], 9);
	c = HH(c, d, a, b, m_x[6], 11);
	b = HH(b, c, d, a, m_x[14], 15);
	a = HH(a, b, c, d, m_x[1], 3);
	d = HH(d, a, b, c, m_x[9], 9);
	c = HH(c, d, a, b, m_x[5], 11);
	b = HH(b, c, d, a, m_x[13], 15);
	a = HH(a, b, c, d, m_x[3], 3);
	d = HH(d, a, b, c, m_x[11], 9);
	c = HH(c, d, a, b, m_x[7], 11);
	b = HH(b, c, d, a, m_x[15], 15);

	m_a += a;
	m_b += b;
	m_c += c;
	m_d += d;

	// Clear m_x
	m_x.fill(0);
}

auto TC::MD::md4(std::istream* const input) -> std::string* const
{
	MD4 inst = MD4();
	return inst.hexdigest(input);
}
