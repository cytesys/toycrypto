#pragma once
#ifndef HEADERSTUFF_H
#define HEADERSTUFF_H

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

#endif