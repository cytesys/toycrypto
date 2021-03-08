#include <string>
#include "toycrypto.hpp"

int main(int argc, char** argv)
{
	std::string output;

	if (argc > 2) {
		std::string hash_type = argv[1];
		std::string input = argv[2];

		if (hash_type.compare("sha1") == 0) {
			output = SHA::sha1(input);
		} else if (hash_type.compare("sha1_file") == 0) {
			output = SHA::sha1_file(input);
		} else if (hash_type.compare("sha224") == 0) {
			output = SHA::sha224(input);
		} else if (hash_type.compare("sha224_file") == 0) {
			output = SHA::sha224_file(input);
		} else if (hash_type.compare("sha256") == 0) {
			output = SHA::sha256(input);
		} else if (hash_type.compare("sha256_file") == 0) {
			output = SHA::sha256_file(input);
		} else if (hash_type.compare("sha384") == 0) {
			output = SHA::sha384(input);
		} else if (hash_type.compare("sha384_file") == 0) {
			output = SHA::sha384_file(input);
		} else if (hash_type.compare("sha512") == 0) {
			output = SHA::sha512(input);
		} else if (hash_type.compare("sha512_file") == 0) {
			output = SHA::sha512_file(input);
		} else if (hash_type.compare("sha512/224") == 0) {
			output = SHA::sha512_224(input);
		} else if (hash_type.compare("sha512/224_file") == 0) {
			output = SHA::sha512_224_file(input);
		} else if (hash_type.compare("sha512/256") == 0) {
			output = SHA::sha512_256(input);
		} else if (hash_type.compare("sha512/256_file") == 0) {
			output = SHA::sha512_256_file(input);
		} else if (hash_type.compare("shake128") == 0) {
			if (argc > 3) {
				output = SHA::shake128(input, atoi(argv[3]));
			} else {
				printf("Error: You must provide an output length for shake128!\n");
				return 1;
			}
		} else if (hash_type.compare("shake256") == 0) {
			if (argc > 3) {
				output = SHA::shake256(input, atoi(argv[3]));
			} else {
				printf("Error: You must provide an output length for shake256!\n");
				return 1;
			}
		} else if (hash_type.compare("sha3-224") == 0) {
			output = SHA::sha3_224(input);
		} else if (hash_type.compare("sha3-256") == 0) {
			output = SHA::sha3_256(input);
		} else if (hash_type.compare("sha3-384") == 0) {
			output = SHA::sha3_384(input);
		} else if (hash_type.compare("sha3-512") == 0) {
			output = SHA::sha3_512(input);
		} else if (hash_type.compare("md2") == 0) {
			output = MD::md2(input);
		} else if (hash_type.compare("md2_file") == 0) {
			output = MD::md2_file(input);
		} else if (hash_type.compare("md4") == 0) {
			output = MD::md4(input);
		} else if (hash_type.compare("md4_file") == 0) {
			output = MD::md4_file(input);
		} else if (hash_type.compare("md5") == 0) {
			output = MD::md5(input);
		} else if (hash_type.compare("md5_file") == 0) {
			output = MD::md5_file(input);
		} else {
			printf("Error: The hash type \"%s\" is not implemented!\n", hash_type.c_str());
			return 1;
		}
	} else {
		printf("Usage: %s <hash_method> <string_to_be_hashed> [output_length]\n", argv[0]);
		return 0;
	}

	printf("%s\n", output.c_str());

	return 0;
}
