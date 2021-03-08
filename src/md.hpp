#pragma once

#ifndef MD2_HPP
#define MD2_HPP

#include "common.hpp"

namespace MD {
	auto md2(const str &input) -> str;
	auto md2_file(const str &filename) -> str;

	auto md4(const str &input) -> str;
	auto md4_file(const str& filename)->str;

	auto md5(const str& input) -> str;
	auto md5_file(const str& filename) -> str;
}

#endif