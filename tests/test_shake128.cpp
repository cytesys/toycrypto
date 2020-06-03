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
		"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
		"f4202e3c5852f9182a0430fd8144f0a7",
		"aabf1874b347dfef851c7a3b2cd31c4f258828458309b67d28e7d545ed3251a7065ef0bf472f0682352acd283106878b0e45695685cb594c42f5091744a2c3a0",
		"87110f594eb1915d5897059dd20cd21615d50f2dd57f268dc80fdc8ccd412b7b",
		"5a66901b47d4ab67ecaa5c2f08888d26"
	};
	
	unsigned int output_length[test_num] = {
		256,
		128,
		512,
		256,
		128
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::shake128(test_strings[i], output_length[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::shake128(test_strings[i], output_length[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
