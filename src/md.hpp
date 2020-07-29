#pragma once

#ifndef MD2_HPP
#define MD2_HPP

#include <string>

namespace MD {
	auto md2(const std::string &input) -> std::string;
	auto md2_file(const std::string &filename) -> std::string;

	auto md4(const std::string &input) -> std::string;
}

#endif