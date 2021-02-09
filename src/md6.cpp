#include <cstdint>
#include <string>
#include <array>
#include <stdexcept>
#include "common.hpp"

/* TODO:
	Not finished!
*/

class MD6 {
protected:
	unsigned int _hashlength;
	unsigned int _rounds;
	std::string _key;

	void _handle();
public:
	MD6(int d, const std::string &K, int r);
	void load_string(const std::string &input);
	auto output() -> std::string;
};

MD6::MD6(int d, const std::string& K, int r) {
	// The hash length "d"
	if (d != 224 && d != 256 && d != 384 && d != 512) {
		throw std::invalid_argument("The hash length is invalid!");
	}

	_hashlength = d;

	// The key "K"
	if (K.length() > 64) {
		throw std::invalid_argument("The key is too long!");
	}
	
	_key = K;

	// Number of rounds "r"
	if (r == 0) {
		if (K.length() == 0) {
			// No key
			_rounds = (40 + (d / 4));
		} else {
			// With key
			_rounds = std::max(80, (40 + (d / 4)));
		}
	}
}
