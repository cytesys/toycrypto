#include "blake.hpp"
#include <iostream>

int main()
{
	std::cout << BLAKE::blake512("The quick brown fox jumps over the lazy dog", "") << std::endl;
	return 0;
}