set(TC_HASH_TESTS
    blake224_test.cpp
    blake256_test.cpp
    blake256_salted_test.cpp
    blake384_test.cpp
    blake384_salted_test.cpp
    blake512_test.cpp
    blake2s_test.cpp
    blake2s_keyed_test.cpp
    blake2b_test.cpp
    blake2b_keyed_test.cpp
    md2_test.cpp
    md4_test.cpp
    md5_test.cpp
    sha1_test.cpp
    sha224_test.cpp
    sha256_test.cpp
    sha384_test.cpp
    sha512_test.cpp
    sha3_224_test.cpp
    sha3_256_test.cpp
    sha3_384_test.cpp
    sha3_512_test.cpp
    shake128_test.cpp
    shake256_test.cpp
)

list(TRANSFORM TC_HASH_TESTS PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/)

set(TC_HASH_TESTS ${TC_HASH_TESTS} PARENT_SCOPE)
