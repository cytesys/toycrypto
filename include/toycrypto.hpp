#pragma once
#ifndef TOYCRYPTO_HPP
#define TOYCRYPTO_HPP

#if defined _WIN32 || defined __CYGWIN__
#define DLL_IMPORT __declspec(dllimport)
#define DLL_EXPORT __declspec(dllexport)
#define DLL_LOCAL
#else
#if __GNUC__ >= 4
#define DLL_IMPORT __attribute__ ((visibility ("default")))
#define DLL_EXPORT __attribute__ ((visibility ("default")))
#define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#else
#define DLL_IMPORT
#define DLL_EXPORT
#define DLL_LOCAL
#endif
#endif

#ifdef toycrypto_EXPORTS
#define TC_API DLL_EXPORT
#else
#define TC_API DLL_IMPORT
#endif
#define TC_LOCAL DLL_LOCAL

#include <iostream>
#include <string>
#include <exception>

extern "C++" {
	namespace TC {
		namespace SHA {
			TC_API auto sha1(std::istream* const infile)->std::string* const;

			TC_API auto sha224(std::istream* const input)->std::string* const;
			TC_API auto sha256(std::istream* const input)->std::string* const;
			TC_API auto sha384(std::istream* const input)->std::string* const;
			TC_API auto sha512(std::istream* const input, unsigned int subtype = 0)->std::string* const;

			TC_API auto shake128(std::istream* const input, unsigned int bitlength)->std::string* const;
			TC_API auto shake256(std::istream* const input, unsigned int bitlength)->std::string* const;
			TC_API auto sha3_224(std::istream* const input)->std::string* const;
			TC_API auto sha3_256(std::istream* const input)->std::string* const;
			TC_API auto sha3_384(std::istream* const input)->std::string* const;
			TC_API auto sha3_512(std::istream* const input)->std::string* const;
		}

		namespace MD {
			TC_API auto md2(std::istream* const input)->std::string* const;
			TC_API auto md4(std::istream* const input)->std::string* const;
			TC_API auto md5(std::istream* const input)->std::string* const;
		}

		namespace BLAKE {
			TC_API auto blake256(std::istream* const input, std::istream* const salt)->std::string* const;
			TC_API auto blake256(std::istream* const input)->std::string* const;
			TC_API auto blake224(std::istream* const input, std::istream* const salt)->std::string* const;
			TC_API auto blake224(std::istream* const input)->std::string* const;
			TC_API auto blake384(std::istream* const input, std::istream* const salt)->std::string* const;
			TC_API auto blake384(std::istream* const input)->std::string* const;
			TC_API auto blake512(std::istream* const input, std::istream* const salt)->std::string* const;
			TC_API auto blake512(std::istream* const input)->std::string* const;

			TC_API auto blake2s(unsigned int bitlength, std::istream* const input)->std::string* const;
			TC_API auto blake2b(unsigned int bitlength, std::istream* const input)->std::string* const;
		}

		namespace exceptions {
			class TC_API TCException : public std::runtime_error {
			public:
				TCException(const char* const message) throw();
				virtual const char* what() const throw();
			};

			class TC_API NotImplementedError : public TC::exceptions::TCException {
			public:
				NotImplementedError(const char* const message) throw();
				virtual const char* what() const throw();
			};
		}
	}
}
#endif
