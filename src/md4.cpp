#include <array>
#include <iostream>

#include "common.hpp"
#include "toycrypto.hpp"

constexpr unsigned int BLOCK_SIZE = 16;
constexpr unsigned int BLOCK_BYTES = BLOCK_SIZE * 4;

constexpr unsigned int H_SIZE = 4;
constexpr std::array<u32, H_SIZE> IV = {
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define FF(a, b, c, d, x, s) (rotateleft<u32>((a) + F((b), (c), (d)) + m_block.at(x), (s)))
#define GG(a, b, c, d, x, s) (rotateleft<u32>((a) + G((b), (c), (d)) + m_block.at(x) + (u32)0x5a827999, (s)))
#define HH(a, b, c, d, x, s) (rotateleft<u32>((a) + H((b), (c), (d)) + m_block.at(x) + (u32)0x6ed9eba1, (s)))

class MD4 {
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
void MD4::print_block() const {
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

auto MD4::hexdigest(std::istream* const input) -> std::string* const {
	// Load input
	load(input);

	// Generate output
	static std::string result = "";
	unsigned int i;

	for (i = 0; i < H_SIZE; i++) {
		result += to_hex<u32>(m_h.at(i), true);
	}

	return &result;
}

void MD4::load(std::istream* const input) {
	char* buffer = new char[BLOCK_BYTES];
	u64 length = 0;
	u64 read = 0;
	unsigned int i;

	// Load input while processing it
	while (input->peek() != EOF) {
		if (!input->good()) {
			throw TC::exceptions::TCException("MD4: Could not read input!");
		}

		input->read(buffer, BLOCK_BYTES);
		read = input->gcount();
		length += read * 8;

		for (i = 0; i < (read / 4); i++) {
			m_block.at(i) = load_le<u32>(buffer, BLOCK_BYTES, i * 4);
		}

		// Load the rest of the bytes
		if ((read % 4) > 0) {
			m_block.at(i) = load_le<u32>(buffer, BLOCK_BYTES, i * 4, read % 4);
		}

		if (read == BLOCK_SIZE) {
			comp();
			read = 0;
		}
	}

	delete[] buffer;

	// Append the padding byte
	m_block.at(read / 4) ^= xor_mask_le<u32>(0x80, read % 4);

	// Process the block if the message length don't fit
	if (read + 8 >= BLOCK_SIZE) {
		comp();
	}

	// Append the message length
	m_block.at(BLOCK_SIZE - 2) = (u32)(length);
	m_block.at(BLOCK_SIZE - 1) = (u32)(length >> 32);

	comp();
}

void MD4::comp()
{
	// for debugging
	//print_block();

	u32 a = m_h.at(0);
	u32 b = m_h.at(1);
	u32 c = m_h.at(2);
	u32 d = m_h.at(3);

	// Round 1
	a = FF(a, b, c, d, 0, 3);
	d = FF(d, a, b, c, 1, 7);
	c = FF(c, d, a, b, 2, 11);
	b = FF(b, c, d, a, 3, 19);
	a = FF(a, b, c, d, 4, 3);
	d = FF(d, a, b, c, 5, 7);
	c = FF(c, d, a, b, 6, 11);
	b = FF(b, c, d, a, 7, 19);
	a = FF(a, b, c, d, 8, 3);
	d = FF(d, a, b, c, 9, 7);
	c = FF(c, d, a, b, 10, 11);
	b = FF(b, c, d, a, 11, 19);
	a = FF(a, b, c, d, 12, 3);
	d = FF(d, a, b, c, 13, 7);
	c = FF(c, d, a, b, 14, 11);
	b = FF(b, c, d, a, 15, 19);

	// Round 2
	a = GG(a, b, c, d, 0, 3);
	d = GG(d, a, b, c, 4, 5);
	c = GG(c, d, a, b, 8, 9);
	b = GG(b, c, d, a, 12, 13);
	a = GG(a, b, c, d, 1, 3);
	d = GG(d, a, b, c, 5, 5);
	c = GG(c, d, a, b, 9, 9);
	b = GG(b, c, d, a, 13, 13);
	a = GG(a, b, c, d, 2, 3);
	d = GG(d, a, b, c, 6, 5);
	c = GG(c, d, a, b, 10, 9);
	b = GG(b, c, d, a, 14, 13);
	a = GG(a, b, c, d, 3, 3);
	d = GG(d, a, b, c, 7, 5);
	c = GG(c, d, a, b, 11, 9);
	b = GG(b, c, d, a, 15, 13);

	// Round 3
	a = HH(a, b, c, d, 0, 3);
	d = HH(d, a, b, c, 8, 9);
	c = HH(c, d, a, b, 4, 11);
	b = HH(b, c, d, a, 12, 15);
	a = HH(a, b, c, d, 2, 3);
	d = HH(d, a, b, c, 10, 9);
	c = HH(c, d, a, b, 6, 11);
	b = HH(b, c, d, a, 14, 15);
	a = HH(a, b, c, d, 1, 3);
	d = HH(d, a, b, c, 9, 9);
	c = HH(c, d, a, b, 5, 11);
	b = HH(b, c, d, a, 13, 15);
	a = HH(a, b, c, d, 3, 3);
	d = HH(d, a, b, c, 11, 9);
	c = HH(c, d, a, b, 7, 11);
	b = HH(b, c, d, a, 15, 15);

	m_h.at(0) += a;
	m_h.at(1) += b;
	m_h.at(2) += c;
	m_h.at(3) += d;

	// Clear m_block
	m_block.fill(0);
}

auto TC::MD::md4(std::istream* const input) -> std::string* const
{
	MD4 inst = MD4();
	return inst.hexdigest(input);
}
