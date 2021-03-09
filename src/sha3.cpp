#include <vector>
#include <cstring>
#include <algorithm>
#include "common.hpp"

#define fi(x, y) 				((x)+5*(y))
#define readlane(x, y)			u8_to_u64((u8*)state+sizeof(u64)*fi(x, y))
#define writelane(x, y, lane)	store_u64_to_u8((u8*)state+sizeof(u64)*fi(x, y), lane)
#define xorlane(x, y, lane)		xor_u64_with_u8((u8*)state+sizeof(u64)*fi(x, y), lane)

int lfsr86540(u8 *lfsr) {
	int result = ((*lfsr) & 0x01) != 0;

	if (((*lfsr) & 0x80) != 0) {
		(*lfsr) = ((*lfsr) << 1) ^ 0x71;
	} else {
		(*lfsr) <<= 1;
	}

	return result;
}

void keccak_f1600(u8 *state) {
	int round, x, y, j, t;
	u8 lfsrstate = 0x01;

	for (round = 0; round < 24; round++) {
		{
			u64 c[5], d;

			for (x = 0; x < 5; x++) {
				c[x] = readlane(x, 0) ^ readlane(x, 1) ^ readlane(x, 2) ^ readlane(x, 3) ^ readlane(x, 4);
			}

			for (x = 0; x < 5; x++) {
				d = c[(x + 4) % 5] ^ leftrotate_u64(c[(x + 1) % 5], 1);
				for (y = 0; y < 5; y++) {
					xorlane(x, y, d);
				}
			}
		}

		{
			u64 current, temp;
			x = 1; y = 0;
			current = readlane(x, y);

			for (t = 0; t < 24; t++) {
				int r = ((t + 1) * (t + 2) / 2) % 64;
				int Y = (2 * x + 3 * y) % 5; x = y; y = Y;
				temp = readlane(x, y);
				writelane(x, y, leftrotate_u64(current, r));
				current = temp;
			}
		}

		{
			u64 temp[5];

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
				int bitpos = (1 << j) - 1;
				if (lfsr86540(&lfsrstate)) {
					xorlane(0, 0, (u64)1 << bitpos);
				}
			}
		}
	}
}

str keccak(int rate, int capacity, str &input, u8 delimeted_suffix, int output_byte_length) {
	std::vector<u8> output;
	u8 state[200];
	u64 rate_in_bytes = rate / 8;
	size_t blocksize = 0;
	size_t input_byte_length = input.length();
	size_t osc = output_byte_length;
	size_t input_offset = 0;
	
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
		blocksize = std::min(static_cast<u64>(input_byte_length), rate_in_bytes);

		for (int i = 0; i < blocksize; i++) {
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
		blocksize = std::min(static_cast<u64>(output_byte_length), rate_in_bytes);
		
		for (int i = 0; i < blocksize; i++) {
			output.push_back(state[i]);
		}
		
		output.push_back((u8)(blocksize & 0xff));
		output_byte_length -= blocksize;

		if (output_byte_length > 0) {
			keccak_f1600(state);
		}
	}

	// Convert the output byte array to hex string
	str hash;
	for (int i = 0; i < osc; i++) {
		hash += u8_to_hex(output[i]);
	}

	return hash;
}

namespace SHA {
	auto shake128(str input, unsigned int output_length) -> str{
		if ((output_length % 8) != 0) {
			throw "The output length must be divisible by 8!";
		}
		
		return keccak(1344, 256, input, 0x1f, output_length / 8);
	}

	auto shake256(str input, unsigned int output_length) -> str {
		if ((output_length % 8) != 0) {
			throw "The output length must be divisible by 8!";
		}
		
		return keccak(1088, 512, input, 0x1f, output_length / 8);
	}

	auto sha3_224(str input) -> str {
		return keccak(1152, 448, input, 0x06, 28);
	}

	auto sha3_256(str input) -> str {
		return keccak(1088, 512, input, 0x06, 32);
	}

	auto sha3_384(str input) -> str {
		return keccak(832, 768, input, 0x06, 48);
	}

	auto sha3_512(str input) -> str {
		return keccak(576, 1024, input, 0x06, 64);
	}
}
