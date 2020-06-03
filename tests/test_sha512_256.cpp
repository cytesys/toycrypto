#include <cstdio>
#include <string>
#include <sha.hpp>

int main() {
	// Tests preparation
	const unsigned int test_num = 5;

	std::string test_strings[test_num] = {
		"",
		"The quick brown fox jumps over the lazy dog",
		"Even a small change in the message will (with overwhelming probability) result in a mostly different hash, due to the avalanche effect. For example, adding a period to the end of the following sentence changes almost half (111 out of 224) of the bits in the hash:",
		"password123??",
		"What's up sheeple!?"
	};

	std::string expected_hashes[test_num] = {
		"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		"dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d",
		"58753e7b4b91d8a12dc67b6094423ff2663059cb6472d85f43813fc6f0fde646",
		"4dfcbc3c19178eb1bc65b9dda494db00ddfa3bf323ed16c70b584c96d44fb969",
		"de0582a46db9d4d041a0e9c5ebf0bd676cdfd7fdd9bfba0fc8556af2765a689c"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha512_256(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha512_256(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
