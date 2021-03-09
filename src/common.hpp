#pragma once

#ifndef COMMON_HPP
#define COMMON_HPP

#include <cstdint>
#include <string>

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;
using str = std::string;

u32 u8_to_u32(u8, u8, u8, u8);
u64 u8_to_u64(u8, u8, u8, u8, u8, u8, u8, u8);
u64 u8_to_u64(const u8*);

void store_u64_to_u8(u8*, u64);
void xor_u64_with_u8(u8*, u64);

u8 leftrotate_u8(u8, unsigned int);
u32 leftrotate_u32(u32, unsigned int);
u64 leftrotate_u64(u64, unsigned int);

u8 rightrotate_u8(u8, unsigned int);
u32 rightrotate_u32(u32, unsigned int);
u64 rightrotate_u64(u64, unsigned int);

u32 reverse_u32(u32);

auto u32_to_hex(u32) -> str;
auto u8_to_hex(u8 a) -> str;

#endif
