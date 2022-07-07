#include <array>
#include <exception>
#include <fstream>
#include <iostream>
#include "common.hpp"

constexpr int CHUNK_SIZE = 64;
constexpr u8 PADDING_BYTE = 0x80;
constexpr std::array<u32, 5> H_INIT = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};
constexpr std::array<u32, 4> K_INIT = {
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6
};

class SHA1 {
public:
	void load_string(const str& input);
	void load_file(const str& filename);
	auto output() const -> str;
private:
	std::array<u32, H_INIT.size()> m_h = H_INIT;
	std::array<u8, CHUNK_SIZE> m_chunk{ {} };

	void handle();

	// For debugging purposes
	//void print_chunk();
};

// For debugging purposes
/* void SHA1::print_chunk()
{
	for (int i = 0; i < m_chunk.size(); i++) {
		printf("%02x ", m_chunk[i]);
		if ((i + 1) % 8 == 0) {
			printf("\n");
		}
	}
	printf("\n");
} */

void SHA1::load_string(const str &input)
{
	size_t length = input.length() * 8;
	size_t offset = 0;
	size_t index = 0;

	// Handle each chunk of the input
	while (input.length() - offset >= CHUNK_SIZE) {
		for (int i = 0; i < CHUNK_SIZE; i++)
			m_chunk.at(i) = input[i + offset];

		handle();
		offset += CHUNK_SIZE;
	}

	// Load the rest of the input into chunk
	for (int i = 0; i < (input.length() - offset); i++) {
		m_chunk.at(i) = input[i + offset];
		index++;
	}

	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK_SIZE)
			m_chunk.at(index++) = 0x00;
		handle();
		index = 0;
	}

	// Pad with zeroes
	while ((index + 8) < CHUNK_SIZE)
		m_chunk.at(index++) = 0x00;

	// Append message length
	for (int i = 56; i >= 0; i-=8)
		m_chunk.at(index++) = (length >> i) & 0xff;

	// Handle the chunk
	handle();
}

void SHA1::load_file(const str &filename)
{
	size_t offset = 0;
	size_t filelen = 0;
	size_t length = 0;
	size_t index;

	// Open file
	char* buffer = new char[CHUNK_SIZE] {};
	std::ifstream infile(filename, std::ifstream::binary);
	if (!infile.good())
		throw "Could not open file!";

	// Get file length
	infile.seekg (0, infile.end);
    filelen = infile.tellg();
	length = filelen * 8;
    infile.seekg (0, infile.beg);

	// Handle each chunk of the infile
	while ((filelen - offset) >= CHUNK_SIZE) {
		infile.read(buffer, CHUNK_SIZE);
		for (int i = 0; i < CHUNK_SIZE; i++)
			m_chunk.at(i) = buffer[i];

		handle();
		offset += CHUNK_SIZE;
	}

	// Set index to the length of the remaining bytes of infile
	index = (filelen % CHUNK_SIZE);

	// Read the remaining bytes of infile and load it into m_chunk
	infile.read(buffer, index);
	for (int i = 0; i < index; i++)
		m_chunk.at(i) = buffer[i];

	infile.close();

	// Apply padding
	m_chunk.at(index++) = PADDING_BYTE;
	if ((index + 8) > CHUNK_SIZE) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK_SIZE)
			m_chunk.at(index++) = 0x00;

		handle();
		index = 0;
	}

	// Pad with zeroes
	while ((index + 8) < CHUNK_SIZE) {
		m_chunk.at(index++) = 0x00;
	}

	// Append message length
	for (int i = 56; i >= 0; i-=8) {
		m_chunk.at(index++) = (length >> i) & 0xff;
	}

	// Handle the chunk
	handle();
}

void SHA1::handle()
{
	std::array<u32, 80> words{ {} };

	// Load words from the chunk into the words-array
	for (int j = 0; j < CHUNK_SIZE / 4; j++) {
		words.at(j) = u8_to_u32(
			m_chunk.at((j * 4)),
			m_chunk.at((j * 4) + 1),
			m_chunk.at((j * 4) + 2),
			m_chunk.at((j * 4) + 3)
		);
	}

	// Extend the words-array to 80 words
	for (int j = CHUNK_SIZE / 4; j < 80; j++) {
		words.at(j) = leftrotate_u32(
			words.at(j-3) ^ words.at(j-8) ^ words.at(j-14) ^ words.at(j-16),
			1
		);
	}

	// Init hash value for this chunk
	u32 a = m_h[0];
	u32 b = m_h[1];
	u32 c = m_h[2];
	u32 d = m_h[3];
	u32 e = m_h[4];

	u32 f, k;

	// Main loop
	for (int j = 0; j < 80; j++) {
		if (j >= 0 && j <= 19) {
			f = (b & c) | ((~b) & d);
			k = K_INIT[0];
		} else if (j >= 20 && j <=39) {
			f = b ^ c ^ d;
			k = K_INIT[1];
		}
		else if (j >= 40 && j <= 59) {
			f = (b & c) | (b & d) | (c & d);
			k = K_INIT[2];
		} else {
			f = b ^ c ^ d;
			k = K_INIT[3];
		}

		u32 temp = leftrotate_u32(a, 5) + f + e + k + words.at(j);
		e = d;
		d = c;
		c = leftrotate_u32(b, 30);
		b = a;
		a = temp;
	}

	m_h[0] += a;
	m_h[1] += b;
	m_h[2] += c;
	m_h[3] += d;
	m_h[4] += e;
}

auto SHA1::output() const -> str
{
	str result = "";

	try {
		for (u32 i : m_h) {
			result += u32_to_hex(i);
		}
	} catch (std::exception const& ex) {
		std::cout << ex.what() << std::endl;
	}

	return result;
}

namespace SHA {
	auto sha1(const str &input) -> str
	{
		SHA1 instance;
		instance.load_string(input);
		return instance.output();
	}

	auto sha1_file(const str &filename) -> str
	{
		SHA1 instance;
		instance.load_file(filename);
		return instance.output();
	}
}