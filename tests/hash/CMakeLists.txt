set(TC_HASH_TESTS
    sha1_test.cpp
    md2_test.cpp
    md4_test.cpp
    md5_test.cpp
)

list(TRANSFORM TC_HASH_TESTS PREPEND ${CMAKE_CURRENT_SOURCE_DIR}/)

set(TC_HASH_TESTS ${TC_HASH_TESTS} PARENT_SCOPE)
