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
		"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		"d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795",
		"7375b59fdd40e47ae306985c89650ebbda3d88b2bdb316ddcf94e40a",
		"338871eb112723d7eb9a98bf5147cae4600e6016d80f385bb0ef0969",
		"03272a49b07cf560a022003b18ea2df036fa8d6f444de5c8d6e2d72e"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha3_224(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha3_224(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
