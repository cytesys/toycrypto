cmake_minimum_required(VERSION 3.12)

project(toycrypto VERSION 2.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Make the library
add_library(toycrypto SHARED
	# Common files
	${PROJECT_SOURCE_DIR}/src/tcexceptions.cpp
	${PROJECT_SOURCE_DIR}/src/common.cpp

	# Message Digest (MD)
	${PROJECT_SOURCE_DIR}/src/md2.cpp
	${PROJECT_SOURCE_DIR}/src/md4.cpp
	${PROJECT_SOURCE_DIR}/src/md5.cpp

	# Secure Hash (SHA)
	${PROJECT_SOURCE_DIR}/src/sha1.cpp
	${PROJECT_SOURCE_DIR}/src/sha2.cpp
	${PROJECT_SOURCE_DIR}/src/sha3.cpp

	# BLAKE
	${PROJECT_SOURCE_DIR}/src/blake.cpp
)

set_target_properties(toycrypto PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(toycrypto PROPERTIES PUBLIC_HEADER ${PROJECT_SOURCE_DIR}/include/toycrypto.hpp)
target_include_directories(toycrypto PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(toycrypto PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Make the toycrypto_exec executable (used for testing primarily)
add_executable(toycrypto_exec ./src/main.cpp)
target_link_libraries(toycrypto_exec PRIVATE toycrypto)
target_include_directories(toycrypto_exec PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Make the executable to run tests on common functions
add_executable(test_common
	${PROJECT_SOURCE_DIR}/src/common.hpp
	${PROJECT_SOURCE_DIR}/src/common.cpp
	${PROJECT_SOURCE_DIR}/src/testing/test_common.cpp
)

# Enable tests
enable_testing()

# Can the application run at all?
add_test(NAME Executes COMMAND toycrypto_exec)
set_tests_properties(Executes
  PROPERTIES PASS_REGULAR_EXPRESSION "Usage: .*output_length\]"
  )

# Test common functionality
add_test(NAME test_common COMMAND test_common)

# Make testfile
set(testfile ${PROJECT_BINARY_DIR}/testfile)
file(WRITE ${testfile} "The quick brown fox jumped over the lazy dog")

# This is a fairly simple cmake function to aid in making automated tests
function(create_test testname algo len text filename)
	# Add the test
	set(fileop (${filename} MATCHES ".+"))
	if(${fileop})
		add_test(NAME ${testname} COMMAND toycrypto_exec ${algo} ${filename} ${len})
	elseif(${text} MATCHES ".+")
		add_test(NAME ${testname} COMMAND toycrypto_exec ${algo}! ${text} ${len})
	else()
		message(SEND_ERROR "The test function call had neither a filename nor text input!")
	endif()
	set_property(TEST ${testname} PROPERTY LABELS test_${algo})

	# Compute the value to compare with
	if(${algo} MATCHES "^md5.*")
		if(${fileop})
			file(MD5 ${filename} computed)
		else()
			string(MD5 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha1.*")
		if(${fileop})
			file(SHA1 ${filename} computed)
		else()
			string(SHA1 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha224.*")
		if(${fileop})
			file(SHA224 ${filename} computed)
		else()
			string(SHA224 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha256.*")
		if(${fileop})
			file(SHA256 ${filename} computed)
		else()
			string(SHA256 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha384.*")
		if(${fileop})
			file(SHA384 ${filename} computed)
		else()
			string(SHA384 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha512.*")
		if(${fileop})
			file(SHA512 ${filename} computed)
		else()
			string(SHA512 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha3_224.*")
		if(${fileop})
			file(SHA3_224 ${filename} computed)
		else()
			string(SHA3_224 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha3_256.*")
		if(${fileop})
			file(SHA3_256 ${filename} computed)
		else()
			string(SHA3_256 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha3_384.*")
		if(${fileop})
			file(SHA3_384 ${filename} computed)
		else()
			string(SHA3_384 computed ${text})
		endif()
	elseif(${algo} MATCHES "^sha3_512.*")
		if(${fileop})
			file(SHA3_512 ${filename} computed)
		else()
			string(SHA3_512 computed ${text})
		endif()
	else()
		message(SEND_ERROR "The hash function ${algo} cannot be tested yet!")
	endif()

	# Compare
	set_tests_properties(${testname}
		PROPERTIES PASS_REGULAR_EXPRESSION "^${computed}\n$"
	)
endfunction(create_test)

# Do a bunch of result based tests
set(hash_functions "sha1;sha224;sha256;sha384;sha512;sha3_224;sha3_256;sha3_384;sha3_512;md5")
foreach(hash_function IN LISTS hash_functions)
	foreach(i RANGE 100)
		math(EXPR testlength "100 + ${i}")
		string(RANDOM LENGTH ${testlength} teststring)
		create_test("test_${hash_function}_${testlength}" "${hash_function}" "" "${teststring}" "")
	endforeach()
	create_test("test_${hash_function}_file" "${hash_function}" "" "" "${testfile}")
endforeach()

# TODO: MD2, MD4 and BLAKE are all outdated, and CMake has neither of them built in, so these cannot
# be automatically tested the same way as those above. I need another program (or maybe multiple programs)
# that can reliably compute these hashes so I can compare the computed hashes from this library with those.
# For now, these hash functions are tested manually.
