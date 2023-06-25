# ToyCrypto

![C/C++ CI](https://github.com/cytesys/toycrypto/workflows/C/C++%20CI/badge.svg?branch=main)
![CodeQL](https://github.com/cytesys/toycrypto/actions/workflows/codeql.yml/badge.svg)
[![Coverity](https://scan.coverity.com/projects/25133/badge.svg)](https://scan.coverity.com/projects/cytesys-toycrypto)

## Introduction

ToyCrypto is a dynamically linked crypto library written in C\+\+. It should work on both *nix-like
systems, MacOSX and Windows.

## *Disclaimer*

*This library is the result of me toying with C++ and crypto (hence the name), and can not be
relied upon to work correctly, obviously \:]*  
***This is for experimental use only! Use at your own risk!***

## What's currently implemented?

ToyCrypto is very much a work in progress, and so far only a few hashing functions has been
implemented:

- [x] SHA2:
    - [x] SHA224
    - [x] SHA256
    - [x] SHA384
    - [x] SHA512
- [x] SHA3:
    - [x] SHA3-224
    - [x] SHA3-256
    - [x] SHA3-384
    - [x] SHA3-512
- [x] SHAKE:
    - [x] SHAKE128
    - [x] SHAKE256
- [x] BLAKE
    - [x] BLAKE224
    - [x] BLAKE256
    - [x] BLAKE384
    - [x] BLAKE512
- [x] BLAKE2
    - [x] BLAKE2s
    - [x] BLAKE2b

The following hash algorithms have also been implemented, but these have been deprecated by NIST.

- [x] ~~MD2~~
- [x] ~~MD4~~
- [x] ~~MD5~~
- [x] ~~SHA1~~

## How to build and test

### Dependencies

- C\+\+20
- CMake 3.16 or higher
- `ninja-build`

I use [GTest](https://github.com/google/googletest/) for testing, and it should be downloaded
automagically when you run cmake \:]

### Building

Building is pretty straight forward\:

```bash
cmake -S . -B build
cmake --build build

# To run the tests
cd build
ctest
```

*Note: CTest appears to only run one test, and that is because all the tests are built into
one single executable named unittests. To see the actual tests you should run the unittests
executable directly. It should be in ./build/tests/ somewhere.*
