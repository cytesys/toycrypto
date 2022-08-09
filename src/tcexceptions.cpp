#include "toycrypto.hpp"

TC::exceptions::TCException::TCException(const char* const message) throw() : std::runtime_error(message)
{

}

const char* TC::exceptions::TCException::what() const throw()
{
	return std::runtime_error::what();
}

TC::exceptions::NotImplementedError::NotImplementedError(const char* const message) throw() : TCException(message)
{

}

const char* TC::exceptions::NotImplementedError::what() const throw()
{
	return TCException::what();
}
