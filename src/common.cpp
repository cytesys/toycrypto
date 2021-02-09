#include <cstdint>
#include <string>

constexpr unsigned int BYTE  = 8;
constexpr unsigned int NIBBLE  = 4;
constexpr uint8_t BYTE_MASK = 0xff;

uint32_t chars_to_uint32_t(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	auto at = static_cast<uint32_t>(a);
	auto bt = static_cast<uint32_t>(b);
	auto ct = static_cast<uint32_t>(c);
	auto dt = static_cast<uint32_t>(d);
	
	return (at << BYTE * 3) | (bt << BYTE * 2) | (ct << BYTE) | dt;
}

uint64_t chars_to_uint64_t(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f, uint8_t g, uint8_t h) {
	auto t0 = static_cast<uint64_t>(chars_to_uint32_t(a, b, c, d));
	auto t1 = static_cast<uint64_t>(chars_to_uint32_t(e, f, g, h));

	return (t0 << BYTE * 4) | t1;
}

uint8_t leftrotate(uint8_t a, unsigned int num) {
	return (a << (num % (sizeof(a) * BYTE))) | (a >> ((sizeof(a) * BYTE) - (num % (sizeof(a) * BYTE))));
}

uint32_t leftrotate(uint32_t a, unsigned int num) {
	return (a << (num % (sizeof(a) * BYTE))) | (a >> ((sizeof(a) * BYTE) - (num % (sizeof(a) * BYTE))));
}

uint64_t leftrotate(uint64_t a, unsigned int num) {
	return (a << (num % (sizeof(a) * BYTE))) | (a >> ((sizeof(a) * BYTE) - (num % (sizeof(a) * BYTE))));
}
uint32_t rightrotate(uint32_t a, unsigned int num) {
    return leftrotate(a, (sizeof(a) * BYTE) - num);
}

uint64_t rightrotate(uint64_t a, unsigned int num) {
    return leftrotate(a, (sizeof(a) * BYTE) - num);
}

uint32_t reverse_endianness(uint32_t a) {
	uint32_t temp = 0;
	for (int i = 0; i < sizeof(a); i++) {
		temp |= (leftrotate(a, (i + 1) * BYTE) & BYTE_MASK) << (i * BYTE);
	}
	return temp;
}

uint64_t reverse_endianness(uint64_t a) {
	uint64_t temp = 0;
	for (int i = 0; i < sizeof(a); i++) {
		temp |= (leftrotate(a, (i + 1) * BYTE) & BYTE_MASK) << (i * BYTE);
	}
	return temp;
}

static auto nibble_to_hex(uint8_t nibble) -> std::string {
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

auto byte_to_hex(uint8_t a) -> std::string {
	std::string result = "";
	for (int i = NIBBLE; i <= sizeof(a) * BYTE; i += NIBBLE) {
		result += nibble_to_hex(leftrotate(a, i) & 0xf);
	}
	return result;
}

auto uint_to_hex(uint32_t a) -> std::string {
	std::string result = "";
	for (int i = NIBBLE; i <= sizeof(a) * BYTE; i += NIBBLE) {
		result += nibble_to_hex(leftrotate(a, i) & 0xf);
	}
	return result;
}
