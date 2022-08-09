#include <string>
#include <exception>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>

//#include <filesystem>
#include <toycrypto.hpp>

int main(int argc, char** argv)
{
	std::string* output;
	std::string hash_type;
	std::string filename;
	std::istream* data;
	int hash_length = 0;

	try {
		// Test
		//std::cout << (-1) % 5 << std::endl;
		//---
		if (argc >= 3) {
			hash_type = argv[1];
			filename = argv[2];
			if (filename.compare("-") == 0) {
				// Read from stdin
				data = &std::cin;
			} else if(hash_type.back() == '!') {
				// Used for testing
				hash_type.pop_back();
				data = new std::istringstream(filename);
			} else {
				//std::filesystem::path filepath {filename};
				//if (std::filesystem::exists(filepath)) {
					//data = new std::ifstream(filepath, std::ifstream::binary);
				struct stat info;
				int status = stat(filename.c_str(), &info);
				if (status == -1) {
					throw TC::exceptions::TCException("File not found!");
				}

				data = new std::ifstream(filename, std::ifstream::binary);
				//} else {
				//	throw TC::exceptions::TCException("The file could not be found!");
				//}
			}

			if (argc >= 4) {
				hash_length = atoi(argv[3]);
			}
		} else {
			std::cout << "Usage: " << argv[0] << " <hash_method> <string_to_be_hashed> [output_length]\n";
			return 0;
		}

		if (hash_type.compare("sha1") == 0) {
			output = TC::SHA::sha1(data);
		} else if (hash_type.compare("sha224") == 0) {
			output = TC::SHA::sha224(data);
		} else if (hash_type.compare("sha256") == 0) {
			output = TC::SHA::sha256(data);
		} else if (hash_type.compare("sha384") == 0) {
			output = TC::SHA::sha384(data);
		} else if (hash_type.compare("sha512") == 0) {
			output = TC::SHA::sha512(data, hash_length);
		} else if (hash_type.compare("shake128") == 0) {
			output = TC::SHA::shake128(data, hash_length);
		} else if (hash_type.compare("shake256") == 0) {
			output = TC::SHA::shake256(data, hash_length);
		} else if (hash_type.compare("sha3_224") == 0) {
			output = TC::SHA::sha3_224(data);
		} else if (hash_type.compare("sha3_256") == 0) {
			output = TC::SHA::sha3_256(data);
		} else if (hash_type.compare("sha3_384") == 0) {
			output = TC::SHA::sha3_384(data);
		} else if (hash_type.compare("sha3_512") == 0) {
			output = TC::SHA::sha3_512(data);
		} else if (hash_type.compare("md2") == 0) {
			output = TC::MD::md2(data);
		} else if (hash_type.compare("md4") == 0) {
			output = TC::MD::md4(data);
		} else if (hash_type.compare("md5") == 0) {
			output = TC::MD::md5(data);
		} else if (hash_type.compare("blake224") == 0) {
			output = TC::BLAKE::blake224(data);
		} else if (hash_type.compare("blake256") == 0) {
			output = TC::BLAKE::blake256(data);
		} else if (hash_type.compare("blake384") == 0) {
			output = TC::BLAKE::blake384(data);
		} else if (hash_type.compare("blake512") == 0) {
			output = TC::BLAKE::blake512(data);
		} else {
			throw TC::exceptions::NotImplementedError("The hash type is not implemented!");
		}
	} catch (std::exception& ex) {
		std::cout << "Error: " << ex.what() << std::endl;
		return 1;
	} catch (const char* ex) {
		std::cout << "Error: " << ex << std::endl;
		return 1;
	}

	std::cout << *output << std::endl;

	return 0;
}
