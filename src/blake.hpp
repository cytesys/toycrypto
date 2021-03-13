#pragma once

#ifndef BLAKE_HPP
#define BLAKE_HPP

#include "common.hpp"

namespace BLAKE {
	auto blake256(const str& input, const str& salt)->str;
	auto blake224(const str& input, const str& salt)->str;
	auto blake384(const str& input, const str& salt)->str;
	auto blake512(const str& input, const str& salt)->str;
}

#endif