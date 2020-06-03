#include <cstdio>
#include <string>
#include <sha.hpp>

int main() {
	// Tests preparation
	const unsigned int test_num = 5;

	std::string test_strings[test_num] = {
		"",
		"The quick brown fox jumps over the lazy dog",
		"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding.",
		"password123??",
		"What's up sheeple!?"
	};

	std::string expected_hashes[test_num] = {
		"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
		"2f671343d9b2e1604dc9dcf0753e5fe1",
		"2cca5df8f0b8b680311d9d1695be4b27f2235df4b4a8ff949bac9d3759f0f77e",
		"cfec6dac20d6ea89c51315571a582ca374231e2d4e5c8adb867b93dee8d717f2",
		"d13a7334d8432eeda73e7dde1070035f"
	};
	
	unsigned int output_length[test_num] = {
		512,
		128,
		256,
		256,
		128
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::shake256(test_strings[i], output_length[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::shake256(test_strings[i], output_length[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
