#include "common.hpp"

u32 u8_to_u32(u8 a, u8 b, u8 c, u8 d)
{
	auto at = static_cast<u32>(a);
	auto bt = static_cast<u32>(b);
	auto ct = static_cast<u32>(c);
	auto dt = static_cast<u32>(d);
	
	return (at << 8 * 3) | (bt << 8 * 2) | (ct << 8) | dt;
}

u64 u8_to_u64(u8 a, u8 b, u8 c, u8 d, u8 e, u8 f, u8 g, u8 h)
{
	auto t0 = static_cast<u64>(u8_to_u32(a, b, c, d));
	auto t1 = static_cast<u64>(u8_to_u32(e, f, g, h));

	return (t0 << 8 * 4) | t1;
}

u64 u8_to_u64(const u8* x)
{
	u64 u = 0;

	for (int i = 7; i >= 0; --i) {
		u <<= 8;
		u |= x[i];
	}

	return u;
}

void store_u64_to_u8(u8* x, u64 u)
{
	for (int i = 0; i < 8; ++i) {
		x[i] = (u & 0xff);
		u >>= 8;
	}
}

void xor_u64_with_u8(u8* x, u64 u)
{
	for (int i = 0; i < 8; ++i) {
		x[i] ^= u;
		u >>= 8;
	}
}

u8 leftrotate_u8(u8 a, unsigned int num)
{
	return (a << (num % (sizeof(a) * 8))) | (a >> ((sizeof(a) * 8) - (num % (sizeof(a) * 8))));
}

u32 leftrotate_u32(u32 a, unsigned int num)
{
	return (a << (num % (sizeof(a) * 8))) | (a >> ((sizeof(a) * 8) - (num % (sizeof(a) * 8))));
}

u64 leftrotate_u64(u64 a, unsigned int num)
{
	return (a << (num % (sizeof(a) * 8))) | (a >> ((sizeof(a) * 8) - (num % (sizeof(a) * 8))));
}

u8 rightrotate_u8(u8 a, unsigned int num)
{
	return leftrotate_u8(a, (sizeof(a) * 8) - num);
}

u32 rightrotate_u32(u32 a, unsigned int num)
{
    return leftrotate_u32(a, (sizeof(a) * 8) - num);
}

u64 rightrotate_u64(u64 a, unsigned int num)
{
    return leftrotate_u64(a, (sizeof(a) * 8) - num);
}

u32 reverse_u32(u32 a)
{
	u32 temp = 0;
	for (int i = 0; i < sizeof(a); i++) {
		temp |= (leftrotate_u32(a, (i + 1) * 8) & 0xff) << (i * 8);
	}
	return temp;
}

static auto nibble_to_hex(u8 nibble) -> str
{
	switch(nibble & 0xf) {
		case 0x0:
			return "0";
			break;
		case 0x1:
			return "1";
			break;
		case 0x2:
			return "2";
			break;
		case 0x3:
			return "3";
			break;
		case 0x4:
			return "4";
			break;
		case 0x5:
			return "5";
			break;
		case 0x6:
			return "6";
			break;
		case 0x7:
			return "7";
			break;
		case 0x8:
			return "8";
			break;
		case 0x9:
			return "9";
			break;
		case 0xa:
			return "a";
			break;
		case 0xb:
			return "b";
			break;
		case 0xc:
			return "c";
			break;
		case 0xd:
			return "d";
			break;
		case 0xe:
			return "e";
			break;
		case 0xf:
			return "f";
			break;
		default:
			return "?";
			break;
	}
}

auto u8_to_hex(u8 a) -> str
{
	str result = "";
	for (int i = 4; i <= sizeof(a) * 8; i += 4) {
		result += nibble_to_hex(leftrotate_u8(a, i) & 0xf);
	}
	return result;
}

auto u32_to_hex(u32 a) -> str
{
	str result = "";
	for (int i = 4; i <= sizeof(a) * 8; i += 4) {
		result += nibble_to_hex(leftrotate_u32(a, i) & 0xf);
	}
	return result;
}
