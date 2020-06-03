#include <cstdio>
#include <string>
#include <sha.hpp>

int main() {
	// Tests preparation
	const unsigned int test_num = 5;

	std::string test_strings[test_num] = {
		"",
		"The quick brown fox jumps over the lazy dog",
		"Implementations of all FIPS-approved security functions can be officially validated through the CMVP program, jointly run by the National Institute of Standards and Technology (NIST) and the Communications Security Establishment (CSE).",
		"password123??",
		"What's up sheeple!?"
	};

	std::string expected_hashes[test_num] = {
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
		"c6a9a72c3f58af1ae526e39354629129a81f156309695721cc79a833",
		"4c420d7528bad04f23d1761264edfac4fa0385627ad02bea413e8b58",
		"1c1db0353bd38b39e0500d632a6a681bab256994f8bd22ffb047a18a"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha224(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
			printf("Got:\n%s\n\n", SHA::sha224(test_strings[i]).c_str());
			printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
			printf("Test failed\n");
			return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
