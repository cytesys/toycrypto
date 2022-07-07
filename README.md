# Toycrypto
![C/C++ CI](https://github.com/cytesys/toycrypto/workflows/C/C++%20CI/badge.svg?branch=master)
[![CodeQL](https://github.com/cytesys/toycrypto/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cytesys/toycrypto/actions/workflows/codeql-analysis.yml)
[![Coverity](https://scan.coverity.com/projects/25133/badge.svg)](https://scan.coverity.com/projects/cytesys-toycrypto)
## Introduction
This is a crypto library written in C++. C++11 and CMake are required. It should work on linux, windows and osx.
This library is not meant to be used for anything, this is just me learning about crypto, C++, CMake and GitHub.

## Currently implemented cryptographic functions
*So far, only hashing functions are implemented.*
- [x] SHA1
- [x] SHA2
- [x] SHA3
- [x] MD2
- [x] MD4
- [x] MD5
- [x] BLAKE

## How to build and test
### Dependencies
#### Un*x:
- CMake 3.20 or higher
- `build-essential`

#### Windows
- Visual Studio (This project was tested with VS Community 2019)
- Support for CMake projects in Visual Studio

### Building
```bash
git clone https://github.com/cytesys/toycrypto.git
cd toycrypto
cmake --preset default
cmake --build --preset default

# To run the tests
cd build
ctest
```
