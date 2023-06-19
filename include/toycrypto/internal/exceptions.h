#pragma once

#ifndef TC_EXCEPTIONS_H
#define TC_EXCEPTIONS_H

#include <stdexcept>
#include <toycrypto/internal/headerstuff.h>

namespace TC {
inline void error_update_after_finalize() {
    throw std::invalid_argument("You cannot run update() after finalize()");
}

inline void error_digest_before_finalize() {
    throw std::invalid_argument("You cannot run digest() before finalize()");
}

inline void error_hexdigest_before_finalize() {
    throw std::invalid_argument("You cannot run hexdigest() before finalize()");
}

inline void error_finalize_after_finalize() {
    throw std::invalid_argument("You cannot run finalize() more than once");
}

inline void error_salt_after_update() {
    throw std::invalid_argument("You cannot run set_salt() after update() or finalize()");
}

inline void error_invalid_output_length() {
    throw std::invalid_argument("The output buffer length is too small");
}

inline void error_invalid_salt_length() {
    throw std::invalid_argument("The salt length is too big");
}

inline void error_invalid_bit_length() {
    throw std::invalid_argument("Invalid bit length");
}
}

#endif
