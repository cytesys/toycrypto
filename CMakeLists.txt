cmake_minimum_required(VERSION 3.0)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# project name
project(cryptotest)

# flags

# files

# include
include_directories(./src)

# target
add_library(cryptotest STATIC
	# Common functions
	./src/common.hpp
	./src/common.cpp
	
	# SHA
	./src/sha.hpp
	./src/sha1.cpp
	./src/sha2.cpp
	./src/sha3.cpp
	
	#MD
	./src/md.hpp
	./src/md2.cpp
	./src/md4.cpp
)
add_executable(bin ./src/main.cpp)

#add_executable(testing ./tests/main.cpp ./tests/sha_test.cpp ./tests/sha_test.hpp)

# ext libs
target_link_libraries(bin cryptotest)
#target_link_libraries(testing cryptotest)

# tests
#enable_testing()
#add_test(sha1_test testing sha1)
#add_test(sha256_test testing sha256)
include(CTest)
add_subdirectory(./tests)
