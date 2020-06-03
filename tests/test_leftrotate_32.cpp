#include <cstdio>
#include <cstdint>
#include <common.hpp>

int main(int argc, char** argv) {
	if (leftrotate((uint32_t)0x12345678, 10) != (uint32_t)0xd159e048) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint32_t)0x80000000, 4) != (uint32_t)0x8) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint32_t)0x88888888, 6) != (uint32_t)0x22222222) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint32_t)0xede84a3f, 5) != (uint32_t)0xbd0947fd) {
		printf("Test failed!\n");
		return 1;
	}
	
	if (leftrotate((uint32_t)0x1, 34) != (uint32_t)0x4) {
		printf("Test failed!\n");
		return 1;
	}
	
	printf("Test passed!\n");
	
	return 0;
}