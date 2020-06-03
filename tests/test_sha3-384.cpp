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
		"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
		"7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41",
		"b8bdd3cc7cdc3b2690e8a5b459152de7f4965030ed67a25746d1fe8d81c5ef42daae24fd0d16007393cfa0a66b0a5a24",
		"e516ddc76d607b0f35d6f51843e2db9d08c3bfffe28eb0c76537d46b7f9f20587d563936b13d9bc3e5287fa1212be25b",
		"9364e37d1c99fbb4bc6b9e73bbd764822d7463ccc6bf9e3085f37987cdb336e59b30bfcfe4a19e96ff881da3a8fd3854"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha3_384(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha3_384(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
