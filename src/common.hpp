#pragma once

#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <string>

uint32_t chars_to_uint32_t(
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t
);

uint64_t chars_to_uint64_t(
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t,
	uint8_t
);

uint32_t leftrotate(uint32_t, unsigned int);
uint64_t leftrotate(uint64_t, unsigned int);
uint32_t rightrotate(uint32_t, unsigned int);
uint64_t rightrotate(uint64_t, unsigned int);
uint32_t reverse_endianness(uint32_t);
uint64_t reverse_endianness(uint64_t);
auto uint_to_hex(uint32_t) ->std::string;
auto byte_to_hex(uint8_t a)->std::string;

#endif
