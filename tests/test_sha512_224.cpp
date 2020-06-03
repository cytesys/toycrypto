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
		"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		"944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37",
		"150c8cc57711a1b2dc3a13793bcaf017ceaafe43b75aeb42251b9a07",
		"328b32267148aac3ab1f86f95d2fd23095f9409517dcd95c6cdbfb77",
		"dc31b789e3ad73fe9c06223221d564a9f50ccff017b9612e45ee54c0"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha512_224(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha512_224(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
