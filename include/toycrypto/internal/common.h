#pragma once

#ifndef TC_COMMON_H
#define TC_COMMON_H

#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <array>
#include <algorithm>
#include <memory>
#include <concepts>

#define ROL(a, n, bits) (((a) << ((n) % (bits))) | ((a) >> ((bits) - ((n) % (bits)))))
#define ROR(a, n, bits) (((a) << ((bits) - ((n) % (bits)))) | ((a) >> ((n) % (bits))))

#endif
