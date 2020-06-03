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
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
		"ed3b702cfcff50cd7c4b6a51f390db298dbee1ae4ba704477cf2ccb7c2d5ab77a19a0e1472000551be8d1180fc1e17a3853e0c697e0a4f6e01d7e48eef0bd098",
		"fdd5d4b69f11d95f7f3b5d27dbbeee8898cbba3b348402b9c83000642d26b67360d2a664cbb2aad3fd31bf399143de4976d2cd9ac4740031ea55b6717fae4b77",
		"8873b84b6f955a4f5f6b4c6a9c200d9c47e7702f381d942f904a769921fcd56254d915aef2fb8af3a0f7d41486f5fc446a9733f519c5df1e74ad4c4f24d6dd1c"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha512(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha512(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
