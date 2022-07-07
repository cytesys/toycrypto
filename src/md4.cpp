#include <array>
#include <cmath>
#include <fstream>
#include <iostream>
#include "common.hpp"


static u32 F(u32 x, u32 y, u32 z) {
	return ((x & y) | ((~x) & z));
}

static u32 G(u32 x, u32 y, u32 z) {
	return ((x & y) | (x & z) | (y & z));
}

static u32 H(u32 x, u32 y, u32 z) {
	return (x ^ y ^ z);
}

static u32 FF(u32 a, u32 b, u32 c, u32 d, u32 x, unsigned int s) {
	return leftrotate_u32(a + F(b, c, d) + x, s);
}

static u32 GG(u32 a, u32 b, u32 c, u32 d, u32 x, unsigned int s) {
	return leftrotate_u32(a + G(b, c, d) + x + (u32)0x5a827999, s);
}

static u32 HH(u32 a, u32 b, u32 c, u32 d, u32 x, unsigned int s) {
	return leftrotate_u32(a + H(b, c, d) + x + (u32)0x6ed9eba1, s);
}

class MD4 {
public:
	void load_string(const str& input);
	void load_file(const str& filename);
	auto output() const -> str;

private:
	std::array<u32, 16> m_x{ {} };
	u32 m_a = 0x67452301;
	u32 m_b = 0xefcdab89;
	u32 m_c = 0x98badcfe;
	u32 m_d = 0x10325476;

	void handle();
};

void MD4::load_string(const str& input)
{
	size_t length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;

	while (input.length() - offset >= 64) {
		// Load bytes from input into the chunk buffer
		// and store data in 32-bit words
		for (int i = 0; i < 16; i++) {
			m_x.at(i) = u8_to_u32(
				input[(i * 4) + offset + 3],
				input[(i * 4) + offset + 2],
				input[(i * 4) + offset + 1],
				input[(i * 4) + offset]
			);
		}

		// Handle
		handle();

		// Increase offset
		offset += 64;
	}

	// Load the remaining whole 32-bit words from input
	if ((input.length() - offset) >= 4) {
		int rem_whole = std::floor((input.length() - offset) / 4);
		size_t new_offset = offset;

		for (int i = 0; i < (rem_whole * 4); i += 4) {
			m_x.at(index++) = u8_to_u32(
				input[i + offset + 3],
				input[i + offset + 2],
				input[i + offset + 1],
				input[i + offset]
			);

			new_offset += 4;
		}

		offset = new_offset;
	}

	// Load the remaining bytes from input
	switch ((input.length() - offset)) {
	case 0:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x00,
			0x00,
			0x80
		);
		break;
	case 1:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x00,
			0x80,
			input[offset]
		);
		break;
	case 2:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x80,
			input[offset + 1],
			input[offset]
		);
		break;
	case 3:
		m_x.at(index++) = u8_to_u32(
			0x80,
			input[offset + 2],
			input[offset + 1],
			input[offset]
		);
		break;
	default:
		break;
	}

	if (index + 2 > 16) {
		while (index < 16) {
			m_x.at(index++) = u8_to_u32(0x00, 0x00, 0x00, 0x00);
		}

		handle();
		index = 0;
	}

	// Pad with zeroes
	while (index + 2 < 16) {
		m_x.at(index++) = u8_to_u32(0x00, 0x00, 0x00, 0x00);
	}

	// Append the message length
	m_x.at(index++) = length & 0xffffffff;
	m_x.at(index++) = leftrotate_u64(length, 32) & 0xffffffff;

	handle();
}

void MD4::load_file(const str &filename)
{
	size_t offset = 0;
	size_t length = 0;
	size_t filelen = 0;
	size_t index = 0;
	size_t buffer_index = 0;

	// Opem the file
	char* buffer = new char[64];
	std::ifstream infile(filename, std::ifstream::binary);
	if (!infile.good())
		throw "Could not open file!";

	// Get file length
	infile.seekg(0, infile.end);
	filelen = infile.tellg();
	length = filelen * 8;
	infile.seekg(0, infile.beg);

	while ((filelen - offset) >= 64) {
		// Load 16 bytes into the chunk
		infile.read(buffer, 64);
		for (int i = 0; i < 16; i++) {
			m_x.at(i) = u8_to_u32(
				buffer[(i * 4) + 3],
				buffer[(i * 4) + 2],
				buffer[(i * 4) + 1],
				buffer[(i * 4)]
			);
		}

		handle();
		offset += 64;
	}

	// Load the remaining whole 32-bit words from input
	if ((filelen - offset) > 0) {
		infile.read(buffer, (filelen - offset));

		if ((filelen - offset) >= 4) {
			int rem_whole = std::floor((filelen - offset) / 4);
			size_t new_offset = offset;

			for (int i = 0; i < (rem_whole * 4); i += 4) {
				m_x.at(index++) = u8_to_u32(
					buffer[i + 3],
					buffer[i + 2],
					buffer[i + 1],
					buffer[i]
				);

				new_offset += 4;
				buffer_index += 4;
			}
			offset = new_offset;
		}
	}

	infile.close();

	switch ((filelen - offset)) {
	case 0:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x00,
			0x00,
			0x80
		);
		break;
	case 1:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x00,
			0x80,
			buffer[buffer_index]
		);
		break;
	case 2:
		m_x.at(index++) = u8_to_u32(
			0x00,
			0x80,
			buffer[buffer_index + 1],
			buffer[buffer_index]
		);
		break;
	case 3:
		m_x.at(index++) = u8_to_u32(
			0x80,
			buffer[buffer_index + 2],
			buffer[buffer_index + 1],
			buffer[buffer_index]
		);
		break;
	default:
		break;
	}

	// Pad with zeroes
	while (index + 2 < 16)
		m_x.at(index++) = u8_to_u32(0x00, 0x00, 0x00, 0x00);

	// Append the message length
	m_x.at(index++) = length & 0xffffffff;
	m_x.at(index++) = leftrotate_u64(length, 32) & 0xffffffff;

	handle();
}

void MD4::handle()
{
	//_debug();

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
}

auto MD4::output() const -> str
{
	str result = "";
	try {
		result += u32_to_hex(reverse_u32(m_a));
		result += u32_to_hex(reverse_u32(m_b));
		result += u32_to_hex(reverse_u32(m_c));
		result += u32_to_hex(reverse_u32(m_d));
	} catch (std::exception const& ex) {
		std::cout << ex.what() << std::endl;
	}
	return result;
}

namespace MD {
	auto md4(const str& input) -> str
	{
		MD4 instance = MD4();
		instance.load_string(input);
		return instance.output();
	}

	auto md4_file(const str& filename) -> str
	{
		MD4 instance = MD4();
		instance.load_file(filename);
		return instance.output();
	}
}