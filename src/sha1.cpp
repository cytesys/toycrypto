#include <string>
#include <cstdint>
#include <array>
#include <exception>
#include <fstream>
#include "common.hpp"

constexpr unsigned int BYTE_SIZE_BITS = 8;
constexpr unsigned int WORD_SIZE_BYTES = 4;
constexpr unsigned int CHUNK_SIZE_BITS = 512;
constexpr unsigned int CHUNK_SIZE_BYTES = 64;
constexpr unsigned int CHUNK_SIZE_WORDS = 16;
constexpr unsigned int W_SIZE = 80;
constexpr uint8_t PADDING_BIT = 0x80;
constexpr uint8_t BYTE_MASK = 0xff;
constexpr std::array<uint32_t, 5> H_INIT = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};
constexpr std::array<uint32_t, 4> K_INIT = {
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6
};

class SHA01 {
	private:
		std::array<uint32_t, H_INIT.size()> _h = H_INIT;
		std::array<uint8_t, CHUNK_SIZE_BYTES> _chunk{{}};
		uint64_t _offset = 0;
		uint64_t _ml = 0;
		int _type;
		
		void _handle();
		//void _print_chunk();
	public:
		explicit SHA01(int sha_type);
		void load_string(const std::string &input);
		void load_file(const std::string &filename);
		auto output() -> std::string;
};

SHA01::SHA01(int sha_type) {
	if (sha_type < 0 || sha_type > 1) {
		throw std::invalid_argument("SHA type must be either 0 or 1!");
	}
	_type = sha_type;
}

// DEBUG
/* void SHA01::_print_chunk() {
	for (int i = 0; i < sizeof(_chunk); i++) {
		printf("%02x ", _chunk[i]);
		if ((i + 1) % 8 == 0) {
			printf("\n");
		}
	}
	printf("\n");
} */

void SHA01::load_string(const std::string &input) {
	// Initialize message length
	_ml = input.length() * BYTE_SIZE_BITS;
	_offset = 0;
	uint64_t i;
	unsigned int index;
	int si;
	
	// Handle each chunk of the input
	while (input.length() - _offset >= CHUNK_SIZE_BYTES) {
		// Load bytes from input into the chunk buffer
		for (i = 0; i < CHUNK_SIZE_BYTES; i++) {
			_chunk.at(i) = input[i + _offset];
		}
		
		// Handle
		_handle();
		
		// Increase offset
		_offset += CHUNK_SIZE_BYTES;
	}
	
	// Load the rest of the input into chunk
	index = 0;
	for (i = 0; i < (input.length() - _offset); i++) {
		_chunk.at(i) = input[i + _offset];
		index++;
	}
	
	// Apply padding
	_chunk.at(index++) = PADDING_BIT;
	if ((index + sizeof(_ml)) > CHUNK_SIZE_BYTES) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK_SIZE_BYTES) {
			_chunk.at(index++) = 0x00;
		}
		_handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + sizeof(_ml)) < CHUNK_SIZE_BYTES) {
		_chunk.at(index++) = 0x00;
	}
	
	// Append message length
	for (si = (sizeof(_ml) - 1); si >= 0; si--) {
		_chunk.at(index++) = (_ml >> (si * BYTE_SIZE_BITS)) & BYTE_MASK;
	}
	
	// Handle the chunk
	_handle();
}

void SHA01::load_file(const std::string &filename) {
	_offset = 0;
	char* buffer = new char[CHUNK_SIZE_BYTES]{};
	unsigned int i;
	unsigned int index;
	
	// Open file
	std::ifstream infile(filename, std::ifstream::binary);
	
	if (!infile.good()) {
		throw std::ios_base::failure("Could not open file!");
	}

	// Get length
	infile.seekg (0, infile.end);
    std::streamoff filelen = infile.tellg();
    infile.seekg (0, infile.beg);
	
	_ml = static_cast<uint64_t>(filelen) * BYTE_SIZE_BITS;
	
	// Handle each chunk of the input
	while ((filelen - _offset) >= CHUNK_SIZE_BYTES) {
		// Load bytes from input into the buffer
		infile.read(buffer, CHUNK_SIZE_BYTES);
		
		// Load bytes from buffer into chunk
		for (i = 0; i < CHUNK_SIZE_BYTES; i++) {
			_chunk.at(i) = buffer[i];
		}
		
		// Handle
		_handle();
		
		// Increase offset
		_offset += CHUNK_SIZE_BYTES;
	}
	
	// Load the rest of the input into buffer
	infile.read(buffer, filelen % CHUNK_SIZE_BYTES);
	
	// Load bytes from buffer into chunk
	for (i = 0; i < (filelen % CHUNK_SIZE_BYTES); i++) {
		_chunk.at(i) = buffer[i];
	}
	
	index = (filelen % CHUNK_SIZE_BYTES);
	
	// Apply padding
	_chunk.at(index++) = PADDING_BIT;
	if ((index + sizeof(_ml)) > CHUNK_SIZE_BYTES) {
		/*
		If there isn't enough space for the message length
		then fill the rest of the chunk with zeroes, handle
		the chunk and continue.
		*/
		while (index < CHUNK_SIZE_BYTES) {
			_chunk.at(index++) = 0x00;
		}
		_handle();
		index = 0;
	}
	
	// Pad with zeroes
	while ((index + sizeof(_ml)) < CHUNK_SIZE_BYTES) {
		_chunk.at(index++) = 0x00;
	}
	
	// Append message length
	for (int si = (sizeof(_ml) - 1); si >= 0; si--) {
		_chunk.at(index++) = (_ml >> (si * BYTE_SIZE_BITS)) & BYTE_MASK;
	}
	
	// Handle the chunk
	_handle();
}

void SHA01::_handle() {
	std::array<uint32_t, W_SIZE> words = {};
	uint64_t j;

	// Load words from the chunk into the words-array
	for (j = 0; j < CHUNK_SIZE_WORDS; j++) {
		words.at(j) = chars_to_uint32_t(
			_chunk.at((j * WORD_SIZE_BYTES)),
			_chunk.at((j * WORD_SIZE_BYTES) + 1),
			_chunk.at((j * WORD_SIZE_BYTES) + 2),
			_chunk.at((j * WORD_SIZE_BYTES) + 3)
		);
	}

	// Extend the words-array to 80 words
	for (j = CHUNK_SIZE_WORDS; j < W_SIZE; j++) {
		if (_type == 0) {
			// SHA0
			words.at(j) = words.at(j-3) ^ words.at(j-8) ^ words.at(j-14) ^ words.at(j-16);
		} else {
			// SHA1
			words.at(j) = leftrotate(
				words.at(j-3) ^ words.at(j-8) ^ words.at(j-14) ^ words.at(j-16),
				1
			);
		}
	}

	// Init hash value for this chunk
	uint32_t a = _h[0];
	uint32_t b = _h[1];
	uint32_t c = _h[2];
	uint32_t d = _h[3];
	uint32_t e = _h[4];

	uint32_t f, k;

	// Main loop
	for (j = 0; j < W_SIZE; j++) {
		if (j >= 0 && j <= 19) {
			f = (b & c) | ((~b) & d);
			k = K_INIT[0];
		} else if (j >= 20 && j <=39) {
			f = b ^ c ^ d;
			k = K_INIT[1];
		} else if (j >= 40 && j <=59) {
			f = (b & c) | (b & d) | (c & d);
			k = K_INIT[2];
		} else if (j >= 60 && j <= 79) {
			f = b ^ c ^ d;
			k = K_INIT[3];
		}

		uint32_t temp = leftrotate(a, 5) + f + e + k + words.at(j);
		e = d;
		d = c;
		c = leftrotate(b, 30);
		b = a;
		a = temp;
	}

	_h[0] += a;
	_h[1] += b;
	_h[2] += c;
	_h[3] += d;
	_h[4] += e;
}

auto SHA01::output() -> std::string {
	std::string result = "";

	for (uint32_t i : _h) {
		result += uint_to_hex(i);
	}

	return result;
}

namespace SHA {
	auto sha0(const std::string &input) -> std::string {
		SHA01 instance(0);
		instance.load_string(input);
		return instance.output();
	}
	
	auto sha1(const std::string &input) -> std::string {
		SHA01 instance(1);
		instance.load_string(input);
		return instance.output();
	}
	
	auto sha0_file(const std::string &filename) -> std::string {
		SHA01 instance(0);
		instance.load_file(filename);
		return instance.output();
	}
	auto sha1_file(const std::string &filename) -> std::string {
		SHA01 instance(1);
		instance.load_file(filename);
		return instance.output();
	}
}