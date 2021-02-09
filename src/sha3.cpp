#include <stdio.h>
#include <cstdint>
#include <inttypes.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include "common.hpp"

static uint64_t load64(const uint8_t *x) {
	int i;
	uint64_t u = 0;

	for (i = 7; i >= 0; --i) {
		u <<= 8;
		u |= x[i];
	}

	return u;
}

static void store64(uint8_t *x, uint64_t u) {
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		x[i] = (u & 0xff);
		u >>= 8;
	}
}

static void xor64(uint8_t *x, uint64_t u) {
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		x[i] ^= u;
		u >>= 8;
	}
}

#define fi(x, y) 				((x)+5*(y))
#define readlane(x, y)			load64((uint8_t*)state+sizeof(uint64_t)*fi(x, y))
#define writelane(x, y, lane)	store64((uint8_t*)state+sizeof(uint64_t)*fi(x, y), lane)
#define xorlane(x, y, lane)		xor64((uint8_t*)state+sizeof(uint64_t)*fi(x, y), lane)

int lfsr86540(uint8_t *lfsr) {
	int result = ((*lfsr) & 0x01) != 0;

	if (((*lfsr) & 0x80) != 0) {
		(*lfsr) = ((*lfsr) << 1) ^ 0x71;
	} else {
		(*lfsr) <<= 1;
	}

	return result;
}

void keccak_f1600(uint8_t *state) {
	unsigned int round, x, y, j, t;
	uint8_t lfsrstate = 0x01;

	for (round = 0; round < 24; round++) {
		{
			uint64_t c[5], d;

			for (x = 0; x < 5; x++) {
				c[x] = readlane(x, 0) ^ readlane(x, 1) ^ readlane(x, 2) ^ readlane(x, 3) ^ readlane(x, 4);
			}

			for (x = 0; x < 5; x++) {
				d = c[(x + 4) % 5] ^ leftrotate(c[(x + 1) % 5], 1);
				for (y = 0; y < 5; y++) {
					xorlane(x, y, d);
				}
			}
		}

		{
			uint64_t current, temp;
			x = 1; y = 0;
			current = readlane(x, y);

			for (t = 0; t < 24; t++) {
				unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
				unsigned int Y = (2 * x + 3 * y) % 5; x = y; y = Y;
				temp = readlane(x, y);
				writelane(x, y, leftrotate(current, r));
				current = temp;
			}
		}

		{
			uint64_t temp[5];

			for (y = 0; y < 5; y++) {
				for (x = 0; x < 5; x++) {
					temp[x] = readlane(x, y);
				}

				for (x = 0; x < 5; x++) {
					writelane(x, y, temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]));
				}
			}
		}

		{
			for (j = 0; j < 7; j++) {
				unsigned int bitpos = (1 << j) - 1;
				if (lfsr86540(&lfsrstate)) {
					xorlane(0, 0, (uint64_t)1 << bitpos);
				}
			}
		}
	}
}

std::string keccak(unsigned int rate, unsigned int capacity, std::string input, uint8_t delimeted_suffix, unsigned int output_byte_length) {
	std::vector<uint8_t> output;
	uint8_t state[200];
	unsigned int rate_in_bytes = rate / 8;
	unsigned int blocksize = 0;
	unsigned int i;
	unsigned int input_byte_length = static_cast<unsigned int>(input.length());
	unsigned int osc = output_byte_length;
	unsigned int input_offset = 0;
	
	if ((rate + capacity) != 1600) {
		throw "The sum of rate and capacity must equal 1600!";
	}

	if ((rate % 8) != 0) {
		throw "The rate must be a multiple of 8!";
	}

	// Initialize the state
	std::memset(state, 0, sizeof(state));

	// Absorb all the input blocks
	while (input_byte_length > 0) {
		blocksize = std::min(input_byte_length, rate_in_bytes);

		for (i = 0; i < blocksize; i++) {
			state[i] ^= input[i + input_offset];
		}

		input += blocksize;
		input_byte_length -= blocksize;
		input_offset += blocksize;

		if (blocksize == rate_in_bytes) {
			keccak_f1600(state);
			blocksize = 0;
		}
	}

	// Do the padding and switch to the squeezing phase
	/*
		Absorb the last few bits and add the forst bit of
		padding (which coincides with the delimeter in
		delimeted_suffix).
	*/
	state[blocksize] ^= delimeted_suffix;

	/*
		If the first bit of padding is at position rate-1, we
		need a whole new block for the second bit of padding.
	*/
	if (((delimeted_suffix & 0x80) != 0) && (blocksize == (rate_in_bytes - 1))) {
		keccak_f1600(state);
	}

	// Add the second bit of padding
	state[rate_in_bytes - 1] ^= 0x80;

	// Switch to the squeezing phase
	keccak_f1600(state);

	// Squeeze all the output blocks
	while (output_byte_length > 0) {
		blocksize = std::min(output_byte_length, rate_in_bytes);
		
		for (i = 0; i < blocksize; i++) {
			output.push_back(state[i]);
		}
		
		output.push_back((uint8_t)(blocksize & 0xff));
		output_byte_length -= blocksize;

		if (output_byte_length > 0) {
			keccak_f1600(state);
		}
	}

	// Convert the output byte array to hex string
	std::string hash;
	for (i = 0; i < osc; i++) {
		hash += byte_to_hex(static_cast<uint8_t>(output[i]));
	}

	return hash;
}

namespace SHA {
	std::string shake128(std::string input, unsigned int output_length) {
		if ((output_length % 8) != 0) {
			throw "The output length must be divisible by 8!";
		}
		
		return keccak(1344, 256, input, 0x1f, output_length / 8);
	}

	std::string shake256(std::string input, unsigned int output_length) {
		if ((output_length % 8) != 0) {
			throw "The output length must be divisible by 8!";
		}
		
		return keccak(1088, 512, input, 0x1f, output_length / 8);
	}

	std::string sha3_224(std::string input) {
		return keccak(1152, 448, input, 0x06, 28);
	}

	std::string sha3_256(std::string input) {
		return keccak(1088, 512, input, 0x06, 32);
	}

	std::string sha3_384(std::string input) {
		return keccak(832, 768, input, 0x06, 48);
	}

	std::string sha3_512(std::string input) {
		return keccak(576, 1024, input, 0x06, 64);
	}
}
