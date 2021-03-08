#include <array>
#include <cmath>
#include <fstream>
#include "common.hpp"

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

void MD5::load_string(const str& input)
{
	size_t length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;

	while (input.length() - offset >= 64) {
		// Load bytes from input into the chunk buffer
		// Store data in 32-bit words
		for (int i = 0; i < 16; i++) {
			m_x.at(i) = u8_to_u32(
				input[(i * 4) + offset + 3],
				input[(i * 4) + offset + 2],
				input[(i * 4) + offset + 1],
				input[(i * 4) + offset]
			);
		}

		handle();
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
	m_x.at(index++) = leftrotate(length, 32) & 0xffffffff;

	handle();
}

void MD5::load_file(const str &filename)
{
	size_t offset = 0;
	size_t filelen = 0;
	size_t length = 0;
	size_t index = 0;
	size_t buffer_index = 0;

	// Open the file
	char* buffer = new char[64];
	std::ifstream infile(filename, std::ifstream::binary);
	if (!infile.good())
		throw std::ios_base::failure("Could not open file!");

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
	m_x.at(index++) = leftrotate(length, 32) & 0xffffffff;

	handle();
}

void MD5::handle()
{
	//_debug();

	u32 a = m_a;
	u32 b = m_b;
	u32 c = m_c;
	u32 d = m_d;

	for (int i = 0; i < 64; i++) {
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
		b = b + leftrotate(f, S[i]);
	}

	m_a += a;
	m_b += b;
	m_c += c;
	m_d += d;
}

auto MD5::output() const -> str
{
	str result = "";
	result += u32_to_hex(reverse_endianness(m_a));
	result += u32_to_hex(reverse_endianness(m_b));
	result += u32_to_hex(reverse_endianness(m_c));
	result += u32_to_hex(reverse_endianness(m_d));
	return result;
}

namespace MD {
	auto md5(const str& input)
	{
		MD5 instance = MD5();
		instance.load_string(input);
		return instance.output();
	}

	auto md5_file(const str& filename)
	{
		MD5 instance = MD5();
		instance.load_file(filename);
		return instance.output();
	}
}