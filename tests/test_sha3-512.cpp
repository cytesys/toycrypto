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
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		"01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450",
		"06dd7aad98c261acf19ba0a7478c77be63e4c571e125c18ea6881f5034339c15ebdb45f891f88a74151ff68b8dc76982007c6c51a81ed624c882b6e8b98a1be8",
		"1e2682d2e00a0e1551233833f6804151ae6837456b39f6ed6326f902084f35d6f80323e2dfec8bb5aebf5707890cbacadff5e9088e49378fae998f60d912c43e",
		"d1d97ae436429c190735e2b33281fdf4667556fd71f60c62bbb8da04304adf383d05a45000671ae0679cdadacb71a4ccb848a6369926845d199444dedce9dcc9"
		};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha3_512(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha3_512(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
