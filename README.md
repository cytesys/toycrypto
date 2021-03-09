# Toycrypto
![C/C++ CI](https://github.com/cytesys/toycrypto/workflows/C/C++%20CI/badge.svg?branch=master)
## Introduction
This is a toy crypto library in C++ in the making. It should work on any platform (that has the C++ standard libraries).
This library is not meant to be used seriously, this is just me learning about crypto, C++, CMake and GitHub.

## Currently implemented cryptographic functions
*So far, only hashing functions are implemented.*
- [x] SHA1
- [x] SHA2
- [x] SHA3
- [x] MD2
- [x] MD4
- [x] MD5

## How to build and test
### Dependencies
You need:
- CMake 3.1 or higher
- build-essential

### Building
```bash
git clone https://github.com/cytesys/toycrypto.git
cd toycrypto
mkdir build && cd build
cmake ..
make -j4

# To run the tests
ctest
```
