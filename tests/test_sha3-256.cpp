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
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
		"b9f01519d6849fd38a8226e3e6cabcde43258d46db4c7be381148d84edef5fb5",
		"2481e08c6558aba2e637b05082c60de5fd2bfdca8a2aa2e97e82ffa53f070c3f",
		"a6328a240a7bdcb8aadef6308dc6bb61ca901947bf6b81387a62952e1e9de261"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha3_256(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha3_256(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
