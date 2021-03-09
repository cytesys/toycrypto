cmake_minimum_required(VERSION 3.1)

# project name
project(toycrypto VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 11)

# target
add_library(toycrypto STATIC
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
	./src/md5.cpp
)

add_executable(toycrypto_exec ./src/main.cpp)

set_target_properties(toycrypto PROPERTIES
    CXX_STANDARD_REQUIRED ON
)

set_target_properties(toycrypto_exec PROPERTIES
    CXX_STANDARD_REQUIRED ON
)

target_link_libraries(toycrypto_exec PUBLIC toycrypto)
target_include_directories(toycrypto_exec PUBLIC
	"${PROJECT_BINARY_DIR}"
    "${PROJECT_SOURCE_DIR}/include"
)

# Tests
enable_testing()

# Does the application run?
add_test(NAME Runs COMMAND toycrypto_exec sha1 abc)

# Does the usage message work?
add_test(NAME Usage COMMAND toycrypto_exec)
set_tests_properties(Usage
  PROPERTIES PASS_REGULAR_EXPRESSION "Usage: .*output_length]"
  )

# Define a function to simplify adding tests
function(do_test name algo arg len result)
  add_test(NAME Comp${name} COMMAND toycrypto_exec ${algo} "${arg}" ${len})
  set_tests_properties(Comp${name}
    PROPERTIES PASS_REGULAR_EXPRESSION ${result}
    )
endfunction(do_test)

# Do a bunch of result based tests
# SHA1
do_test("SHA1_normal" "sha1"
	"The quick brown fox jumps over the lazy dog"
	""
	"^2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n$"
)
do_test("SHA1_empty" "sha1" 
	""
	""
	"^da39a3ee5e6b4b0d3255bfef95601890afd80709\n$"
)
do_test("SHA1_long" "sha1" 
	"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	""
	"^5a9c3269c60c73029c6459e622a063293e072aa2\n$"
)

# SHA224
do_test("SHA224_normal" "sha224"
	"The quick brown fox jumps over the lazy dog"
	""
	"^730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\n$"
)
do_test("SHA224_empty" "sha224" 
	""
	""
	"^d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\n$"
)
do_test("SHA224_long" "sha224" 
	"Implementations of all FIPS-approved security functions can be officially validated through the CMVP program, jointly run by the National Institute of Standards and Technology (NIST) and the Communications Security Establishment (CSE)."
	""
	"^c6a9a72c3f58af1ae526e39354629129a81f156309695721cc79a833\n$"
)

# SHA256
do_test("SHA256_normal" "sha256"
	"The quick brown fox jumps over the lazy dog"
	""
	"^d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\n$"
)
do_test("SHA256_empty" "sha256"
	""
	""
	"^e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n$"
)
do_test("SHA256_long" "sha256"
	"32-bit implementations of SHA-512 are significantly slower than their 64-bit counterparts. Variants of both algorithms with different output sizes will perform similarly, since the message expansion and compression functions are identical, and only the initial hash values and output sizes are different. The best implementations of MD5 and SHA-1 perform between 4.5 and 6 cycles per byte on modern processors."
	""
	"^bc98976935410a363bbc559fcc333df3d9e9faf28c6e89cf2925be43f5ae510f\n$"
)

# SHA384
do_test("SHA384_normal" "sha384"
	"The quick brown fox jumps over the lazy dog"
	""
	"^ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1\n$"
)
do_test("SHA384_empty" "sha384"
	""
	""
	"^38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n$"
)
do_test("SHA384_long" "sha384"
	"Even a small change in the message will (with overwhelming probability) result in a mostly different hash, due to the avalanche effect. For example, adding a period to the end of the following sentence changes almost half (111 out of 224) of the bits in the hash:"
	""
	"^0b2d2fc5edd4fd40a2e63c8897408505bc4832bb3b0099342d327e021b392c77d1266c9e5a6cdf0121270ca26378cde6\n$"
)

# SHA512
do_test("SHA512_normal" "sha512"
	"The quick brown fox jumps over the lazy dog"
	""
	"^07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6\n$"
)
do_test("SHA512_empty" "sha512"
	""
	""
	"^cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n$"
)
do_test("SHA512_long" "sha512"
	"Even a small change in the message will (with overwhelming probability) result in a mostly different hash, due to the avalanche effect. For example, adding a period to the end of the following sentence changes almost half (111 out of 224) of the bits in the hash:"
	""
	"^ed3b702cfcff50cd7c4b6a51f390db298dbee1ae4ba704477cf2ccb7c2d5ab77a19a0e1472000551be8d1180fc1e17a3853e0c697e0a4f6e01d7e48eef0bd098\n$"
)

# SHA512/224
do_test("SHA512/224_normal" "sha512/224"
	"The quick brown fox jumps over the lazy dog"
	""
	"^944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37\n$"
)
do_test("SHA512/224_empty" "sha512/224"
	""
	""
	"^6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4\n$"
)
do_test("SHA512/224_long" "sha512/224"
	"Even a small change in the message will (with overwhelming probability) result in a mostly different hash, due to the avalanche effect. For example, adding a period to the end of the following sentence changes almost half (111 out of 224) of the bits in the hash:"
	""
	"^150c8cc57711a1b2dc3a13793bcaf017ceaafe43b75aeb42251b9a07\n$"
)

# SHA512/256
do_test("SHA512/256_normal" "sha512/256"
	"The quick brown fox jumps over the lazy dog"
	""
	"^dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d\n$"
)
do_test("SHA512/256_empty" "sha512/256"
	""
	""
	"^c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a\n$"
)
do_test("SHA512/256_long" "sha512/256"
	"Even a small change in the message will (with overwhelming probability) result in a mostly different hash, due to the avalanche effect. For example, adding a period to the end of the following sentence changes almost half (111 out of 224) of the bits in the hash:"
	""
	"^58753e7b4b91d8a12dc67b6094423ff2663059cb6472d85f43813fc6f0fde646\n$"
)

# SHA3-224
do_test("SHA3-224_normal" "sha3-224"
	"The quick brown fox jumps over the lazy dog"
	""
	"^d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795\n$"
)
do_test("SHA3-224_empty" "sha3-224"
	""
	""
	"^6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7\n$"
)
do_test("SHA3-224_long" "sha3-224"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	""
	"^7375b59fdd40e47ae306985c89650ebbda3d88b2bdb316ddcf94e40a\n$"
)

# SHA3-256
do_test("SHA3-256_normal" "sha3-256"
	"The quick brown fox jumps over the lazy dog"
	""
	"^69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04\n$"
)
do_test("SHA3-256_empty" "sha3-256"
	""
	""
	"^a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n$"
)
do_test("SHA3-256_long" "sha3-256"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	""
	"^b9f01519d6849fd38a8226e3e6cabcde43258d46db4c7be381148d84edef5fb5\n$"
)

# SHA3-384
do_test("SHA3-384_normal" "sha3-384"
	"The quick brown fox jumps over the lazy dog"
	""
	"^7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41\n$"
)
do_test("SHA3-384_empty" "sha3-384"
	""
	""
	"^0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004\n$"
)
do_test("SHA3-384_long" "sha3-384"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	""
	"^b8bdd3cc7cdc3b2690e8a5b459152de7f4965030ed67a25746d1fe8d81c5ef42daae24fd0d16007393cfa0a66b0a5a24\n$"
)

# SHA3-512
do_test("SHA3-512_normal" "sha3-512"
	"The quick brown fox jumps over the lazy dog"
	""
	"^01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450\n$"
)
do_test("SHA3-512_empty" "sha3-512"
	""
	""
	"^a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26\n$"
)
do_test("SHA3-512_long" "sha3-512"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	""
	"^06dd7aad98c261acf19ba0a7478c77be63e4c571e125c18ea6881f5034339c15ebdb45f891f88a74151ff68b8dc76982007c6c51a81ed624c882b6e8b98a1be8\n$"
)

# SHAKE128
do_test("SHAKE128_normal" "shake128"
	"The quick brown fox jumps over the lazy dog"
	"128"
	"^f4202e3c5852f9182a0430fd8144f0a7\n$"
)
do_test("SHAKE128_empty" "shake128"
	""
	"256"
	"^7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\n$"
)
do_test("SHAKE128_long" "shake128"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	"512"
	"^aabf1874b347dfef851c7a3b2cd31c4f258828458309b67d28e7d545ed3251a7065ef0bf472f0682352acd283106878b0e45695685cb594c42f5091744a2c3a0\n$"
)

# SHAKE256
do_test("SHAKE256_normal" "shake256"
	"The quick brown fox jumps over the lazy dog"
	"128"
	"^2f671343d9b2e1604dc9dcf0753e5fe1\n$"
)
do_test("SHAKE256_empty" "shake256"
	""
	"512"
	"^46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\n$"
)
do_test("SHAKE256_long" "shake256"
	"For SHA-3-224, SHA-3-256, SHA-3-384, and SHA-3-512 instances, r is greater than d, so there is no need for additional block permutations in the squeezing phase; the leading d bits of the state are the desired hash. However, SHAKE-128 and SHAKE-256 allow an arbitrary output length, which is useful in applications such as optimal asymmetric encryption padding."
	"256"
	"^2cca5df8f0b8b680311d9d1695be4b27f2235df4b4a8ff949bac9d3759f0f77e\n$"
)

# MD2
do_test("MD2_normal" "md2"
	"The quick brown fox jumps over the lazy dog"
	""
	"^03d85a0d629d2c442e987525319fc471\n$"
)
do_test("MD2_empty" "md2"
	""
	""
	"^8350e5a3e24c153df2275c9f80692773\n$"
)
do_test("MD2_long" "md2"
	"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	""
	"^d107d6485c9106eddd331c61078ed3c4\n$"
)

# MD4
do_test("MD4_normal" "md4"
	"The quick brown fox jumps over the lazy dog"
	""
	"^1bee69a46ba811185c194762abaeae90\n$"
)
do_test("MD4_empty" "md4"
	""
	""
	"^31d6cfe0d16ae931b73c59d7e0c089c0\n$"
)
do_test("MD4_long" "md4"
	"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	""
	"^999e0b4b552614faf1fa6a5e58d8b97b\n$"
)

# MD5
do_test("MD5_normal" "md5"
	"The quick brown fox jumps over the lazy dog"
	""
	"^9e107d9d372bb6826bd81d3542a419d6\n$"
)
do_test("MD5_empty" "md5"
	""
	""
	"^d41d8cd98f00b204e9800998ecf8427e\n$"
)
do_test("MD5_long" "md5"
	"However they were incorrectly rounded to the nearest integer instead of being rounded to the nearest odd integer, with equilibrated proportions of zero and one bits."
	""
	"^d3bf3ebaeb624f7528e1fabc760e82d5\n$"
)
