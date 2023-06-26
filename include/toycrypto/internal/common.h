#pragma once

#ifndef TC_COMMON_H
#define TC_COMMON_H

#define __STDC_FORMAT_MACROS
#include <cstdint>
#include <iostream>
#include <array>
#include <concepts>
#include <string>
#include <vector>
#include <stdexcept>
#include <cinttypes>
#include <algorithm>

template<class T>
inline T ror(T a, unsigned n) {
    return (a << (((sizeof(T) << 3) - n) % (sizeof(T) << 3))) | (a >> (n % (sizeof(T) << 3)));
}

template<class T>
inline T rol(T a, unsigned n) {
    return (a << (n % (sizeof(T) << 3))) | (a >> (((sizeof(T) << 3) - n) % (sizeof(T) << 3)));
}

template<class T>
inline T ror_be(T a, unsigned i) {
    return ror<T>(a, ((i + 1) % sizeof(T)) << 3);
}

template<class T>
inline T rol_be(T a, unsigned i) {
    return rol<T>(a, ((i + 1) % sizeof(T)) << 3);
}

template<class T>
inline T ror_le(T a, unsigned i) {
    return ror<T>(a, (i % sizeof(T)) << 3);
}

template<class T>
inline T rol_le(T a, unsigned i) {
    return rol<T>(a, (i % sizeof(T)) << 3);
}

#endif
