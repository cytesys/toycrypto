#pragma once

#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <string>

/**
 * A helper function to convert four bytes to
 * a big-endian uint32_t.
 *
 * @param a 	The first byte.
 * @param b 	The second byte.
 * @param c 	The third byte.
 * @param d 	The fourth byte.
 *
 * @returns 	The four input bytes concatinated to a
 * big-endian uint32_t.
 */
auto chars_to_uint32_t(
	uint8_t a,
	uint8_t b,
	uint8_t c,
	uint8_t d
) -> uint32_t;

/**
 * A helper function to convert eight bytes to
 * a big-endian uint64_t.
 *
 * @param a 	The first byte.
 * @param b 	The second byte.
 * @param c 	The third byte.
 * @param d 	The fourth byte.
 * @param e 	The fifth byte.
 * @param f 	The sixth byte.
 * @param g 	The seventh byte.
 * @param h 	The eight byte.
 *
 * @returns 	The eight input bytes concatinated to a
 * big-endian uint64_t.
 */
auto chars_to_uint64_t(
	uint8_t a,
	uint8_t b,
	uint8_t c,
	uint8_t d,
	uint8_t e,
	uint8_t f,
	uint8_t g,
	uint8_t h
) -> uint64_t;

/**
 * A helper function to left rotate a uint32_t
 * by a arbitrary number.
 *
 * @param a		The uint32_t that will be rotated.
 * @param num 	The number of rotations.
 *
 * @returns 	The result.
 */
auto leftrotate(uint32_t a, unsigned int num) -> uint32_t;

/**
 * A helper function to left rotate a uint64_t
 * by a arbitrary number.
 *
 * @param a		The uint64_t that will be rotated.
 * @param num 	The number of rotations.
 *
 * @returns 	The result.
 */
auto leftrotate(uint64_t a, unsigned int num) -> uint64_t;

/**
 * A helper function to right rotate a uint32_t
 * by a arbitrary number.
 *
 * @param a		The uint32_t that will be rotated.
 * @param num 	The number of rotations.
 *
 * @returns 	The result.
 */
auto rightrotate(uint32_t a, unsigned int num) -> uint32_t;

/**
 * A helper function to right rotate a uint64_t
 * by a arbitrary number.
 *
 * @param a		The uint64_t that will be rotated.
 * @param num 	The number of rotations.
 *
 * @returns 	The result.
 */
auto rightrotate(uint64_t a, unsigned int num) -> uint64_t;

/**
 * A helper function to reverse the endianness
 * of a uint32_t. If the number is big-endian,
 * this function will change it to little-endian,
 * and vice-versa.
 *
 * @param a		The uint32_t that will be changed.
 *
 * @returns 	The result.
 */
auto reverse_endianness(uint32_t a) -> uint32_t;

/**
 * A helper function to reverse the endianness
 * of a uint32_t. If the number is big-endian,
 * this function will change it to little-endian,
 * and vice-versa.
 *
 * @param a		The uint32_t that will be changed.
 *
 * @returns 	The result.
 */
auto reverse_endianness(uint64_t a) -> uint64_t;

/**
 * A helper function to convert a uint32_t to a hex
 * string.
 *
 * @param a		The uint32_t that will be converted.
 *
 * @returns 	The hex string.
 */
auto uint_to_hex(uint32_t a) -> std::string;

#endif
