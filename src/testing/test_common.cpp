#include <iostream>

#include "../common.hpp"

#define BSIZE 0x20

void test_load_be() {
	// Initializing
	// Make a buffer and fill it with numbers 0..<sizeof(buffer)>
	char* buffer = new char[BSIZE];
	for (int i = 0; i < BSIZE; i++) {
		buffer[i] = i;
	}

	// Test load_be<u32>()
	u32 temp = load_be<u32>(buffer, BSIZE, 0);
	if (!(temp == 0x00010203)) {
		std::cout << "load_be<u32> #0 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_be<u32>(buffer, BSIZE, 0x10);
	if (!(temp == 0x10111213)) {
		std::cout << "load_be<u32> #1 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_be<u32>(buffer, BSIZE, 8, 3);
	if (!(temp == 0x08090a00)) {
		std::cout << "load_be<u32> #2 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_be<u32>(buffer, BSIZE, 0x0e, 2);
	if (!(temp == 0x0e0f0000)) {
		std::cout << "load_be<u32> #3 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	do {
		try {
			temp = load_be<u32>(buffer, BSIZE, BSIZE - 3, 4);
		}
		catch (...) {
			break;
		}
		std::cout << "load_be<u32> #4 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	do {
		try {
			temp = load_be<u32>(buffer, BSIZE, BSIZE, 2);
		}
		catch (...) {
			break;
		}
		std::cout << "load_be<u32> #5 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	do {
		try {
			temp = load_be<u32>(buffer, BSIZE, -1);
		}
		catch (...) {
			break;
		}
		std::cout << "load_be<u32> #6 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	temp = load_be<u32>(buffer, BSIZE, 1, -1);
	if (!(temp == 0x01020304)) {
		std::cout << "load_be<u32> #7 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_be<u32>(buffer, BSIZE, 7, 0);
	if (!(temp == 0)) {
		std::cout << "load_be<u32> #8 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_be<u32>(buffer, BSIZE, 0, 10);
	if (!(temp == 0x00010203)) {
		std::cout << "load_be<u32> #9 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	delete[] buffer;
}

void test_load_le() {
	// Initializing
	// Make a buffer and fill it with numbers 0..<sizeof(buffer)>
	char* buffer = new char[BSIZE];
	for (int i = 0; i < BSIZE; i++) {
		buffer[i] = i;
	}

	// Test load_le<u32>()
	u32 temp = load_le<u32>(buffer, BSIZE, 0);
	if (!(temp == 0x03020100)) {
		std::cout << "load_le<u32> #0 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_le<u32>(buffer, BSIZE, 0, 3);
	if (!(temp == 0x00020100)) {
		std::cout << "load_le<u32> #1 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_le<u32>(buffer, BSIZE, 0x10);
	if (!(temp == 0x13121110)) {
		std::cout << "load_le<u32> #2 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_le<u32>(buffer, BSIZE, 0x10, 2);
	if (!(temp == 0x00001110)) {
		std::cout << "load_le<u32> #3 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	do {
		try {
			temp = load_le<u32>(buffer, BSIZE, BSIZE - 3, 4);
		}
		catch (...) {
			break;
		}
		std::cout << "load_le<u32> #4 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	do {
		try {
			temp = load_le<u32>(buffer, BSIZE, BSIZE, 2);
		}
		catch (...) {
			break;
		}
		std::cout << "load_le<u32> #5 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	do {
		try {
			temp = load_le<u32>(buffer, BSIZE, -1);
		}
		catch (...) {
			break;
		}
		std::cout << "load_le<u32> #6 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	} while (true == false);

	temp = load_le<u32>(buffer, BSIZE, 1, -1);
	if (!(temp == 0x04030201)) {
		std::cout << "load_le<u32> #7 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_le<u32>(buffer, BSIZE, 7, 0);
	if (!(temp == 0)) {
		std::cout << "load_le<u32> #8 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = load_le<u32>(buffer, BSIZE, 0, 10);
	if (!(temp == 0x03020100)) {
		std::cout << "load_le<u32> #9 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}
}

void test_rotateleft() {
	u32 test = 1;
	u32 temp = rotateleft<u32>(test, 63);
	if (!(temp == 0x80000000)) {
		std::cout << "rotateleft #0 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	test = 0x80000001;
	temp = rotateleft<u32>(test, 1);
	if (!(temp == 3)) {
		std::cout << "rotateleft #1 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	u8 testbyte = 0xaa;
	u8 tempbyte = rotateleft<u8>(testbyte, 5);
	if (!(tempbyte == 0x55)) {
		std::cout << "rotateleft #2 failed: got 0x" << to_hex<u8>(tempbyte) << std::endl;
		exit(1);
	}
}

void test_rotateright() {
	u32 test = 0xabcdef91;
	u32 temp = rotateright<u32>(test, 4);
	if (!(temp == 0x1abcdef9)) {
		std::cout << "rotateright #0 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}

	temp = rotateright<u32>(test, 7);
	if (!(temp == 0x23579bdf)) {
		std::cout << "rotateright #1 failed: got 0x" << to_hex<u32>(temp) << std::endl;
		exit(1);
	}
}

void test_to_hex() {
	str temp;
	temp = to_hex<u8>(0xab);
	if (!(temp.compare("ab") == 0)) {
		std::cout << "to_hex #0 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u16>(0xabcd);
	if (!(temp.compare("abcd") == 0)) {
		std::cout << "to_hex #1 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u32>(0x12345678);
	if (!(temp.compare("12345678") == 0)) {
		std::cout << "to_hex #2 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u64>(0x12345678abcdef09);
	if (!(temp.compare("12345678abcdef09") == 0)) {
		std::cout << "to_hex #3 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u8>(0xab, true);
	if (!(temp.compare("ab") == 0)) {
		std::cout << "to_hex #4 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u16>(0xabcd, true);
	if (!(temp.compare("cdab") == 0)) {
		std::cout << "to_hex #5 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u32>(0x12345678, true);
	if (!(temp.compare("78563412") == 0)) {
		std::cout << "to_hex #6 failed: got " << temp << std::endl;
		exit(1);
	}

	temp = to_hex<u64>(0xabcd1234cdef5678, true);
	if (!(temp.compare("7856efcd3412cdab") == 0)) {
		std::cout << "to_hex #7 failed: got " << temp << std::endl;
		exit(1);
	}
}

int main(int argc, char** argv) {
	test_load_be();
	test_load_le();
	test_rotateleft();
	test_rotateright();
	test_to_hex();

	// Passed
	std::cout << "All tests passed!" << std::endl;
}