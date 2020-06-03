#include <cstdio>
#include <string>
#include <sha.hpp>

int main(int argc, char** argv) {
	// Tests preparation
	const unsigned int test_num = 5;

	std::string test_strings[test_num] = {
		"The quick brown fox jumps over the lazy dog",
		"The quick brown fox jumps over the lazy cog",
		"",
		"password",
		"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	};

	std::string expected_hashes[test_num] = {
		"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
		"de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
		"5a9c3269c60c73029c6459e622a063293e072aa2"
	};

	//Running the tests
	for (unsigned int i = 0; i < test_num; i++) {
		if (SHA::sha1(test_strings[i]).compare(expected_hashes[i]) != 0) {
			printf("Testing this:\n%s\n\n", test_strings[i].c_str());
            printf("Got:\n%s\n\n", SHA::sha1(test_strings[i]).c_str());
            printf("Expected:\n%s\n\n", expected_hashes[i].c_str());
            printf("Test failed\n");
            return 1;
		}
	}

	printf("Test passed\n");

	return 0;
}
