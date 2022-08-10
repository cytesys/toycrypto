# Toycrypto
![C/C++ CI](https://github.com/cytesys/toycrypto/workflows/C/C++%20CI/badge.svg?branch=main)
![CodeQL](https://github.com/cytesys/toycrypto/actions/workflows/codeql.yml/badge.svg)
[![Coverity](https://scan.coverity.com/projects/25133/badge.svg)](https://scan.coverity.com/projects/cytesys-toycrypto)
## Introduction
This is a dynamically linked crypto library written in C++.
C++17 and CMake 3.12 or higher are required. It should work on Linux, Windows and MacOS. The only required library is the standard library.

## Currently implemented cryptographic functions
*So far, only hashing functions are implemented.*
- [x] SHA1
- [x] SHA2
- [x] SHA3
- [x] MD2
- [x] MD4
- [x] MD5
- [ ] MD6
- [x] BLAKE
- [ ] BLAKE2

## How to build and test
### Dependencies
You will need:

#### On Linux:
- CMake 3.12 or higher
- `build-essential`
- `ninja-build`

#### On Windows
- Visual Studio (This project was built and tested locally with Visual Studio Community 2017, 2019 and 2022)
- Support for CMake Projects in Visual Studio

#### On MacOS
- CMake 3.12 or higher
- `ninja-build`

##### Installing MacOS dependencies via homebrew
```bash
brew install cmake ninja
```

### Building
```bash
git clone https://github.com/cytesys/toycrypto.git
cd toycrypto
cmake --preset default -S . -B build
cmake --build build

# To run the tests
cd build
ctest
```

### Disclaimer
This library is not really made for any serious usage. It should not be used for anything other than tinkering and experimenting.
