# toycrypto
![C/C++ CI](https://github.com/cytesys/toycrypto/workflows/C/C++%20CI/badge.svg?branch=master)
## Introduction
This is a toy crypto library in C++ in the making. It has no dependencies, and should work on any platform (that has C++ standard libraries).
This project has an executable (bin.exe), mostly for testing purposes, and CMake tests for every crypto- and helper function.

## Currently implemented cryptographic functions
*So far, only cryptographic hashing functions are implemented.*
- [x] SHA0
- [x] SHA1
- [x] SHA2
- [x] SHA3
- [x] MD2
- [x] MD4
- [x] MD5
- [ ] MD6

## How to build and test
```bash
git clone git@github.com:cytesys/toycrypto.git
cd toycrypto
mkdir build && cd build
cmake ..
make -j 4 && make test
```
---
***This library is not meant to be used seriously, this is just me learning about crypto, C++, CMake and GitHub.***
