#pragma once

#ifndef MD2_HPP
#define MD2_HPP

#include <string>

namespace MD {
	auto md2(const std::string &input) -> std::string;
	std::string md4(std::string input);
}

#endif