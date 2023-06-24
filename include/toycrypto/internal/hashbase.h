#pragma once

#ifndef TC_HASHBASE_H
#define TC_HASHBASE_H

#define __STDC_FORMAT_MACROS

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/common.h>
#include <toycrypto/hash/hash_common.h>
#include <toycrypto/common/util.h>

extern "C++" {
template<typename T>
concept HBC = std::is_integral<T>::value && std::is_unsigned<T>::value;

template<HBC T, size_t BS, bool BE>
class HBase {
public:
    TC_API virtual ~HBase() = 0;

    TC_API virtual void reset();

    TC_API void update(const char* _buffer, size_t buflen);

    TC_API virtual void finalize() = 0;

    TC_API void digest(unsigned char* output, size_t outlen);

    TC_API std::string hexdigest();

    TC_API inline size_t get_digestsize() const { return m_digestsize; }

protected:
    virtual void init_state() = 0;
    virtual void process_block() = 0;

    void pad_md();

    void pad_haifa();

    void append_length();

    void set_digestsize(size_t dsize);

    void print_block() const;

    void print_state() const;

    inline void clear_block() { m_block.assign(BS, 0); }

    inline void clear_length() { m_length = 0; }

    inline void inc_length() { m_length++; }

    inline void inc_length(size_t len) { m_length += len; }

    inline void clear_counter() { m_counter = 0; }

    inline void inc_counter() { m_counter++; }

    inline void inc_counter(size_t len) { m_counter += len; }

    inline size_t get_length() const { return m_length; }

    inline size_t get_length_bits() const { return m_length << 3; }

    inline size_t get_counter() const { return m_counter; }

    inline size_t get_index() const { return m_counter / sizeof(T); }

    inline HashState get_phase() const { return m_phase; }

    inline void set_phase(HashState phase) { m_phase = phase; }

    inline size_t get_blocksize() const { return m_block.size(); }

    inline size_t get_blocksize_bytes() const { return m_block.size() * sizeof(T); }

    inline size_t get_blocksize_bits() const { return get_blocksize_bytes() << 3; }

    inline size_t get_statesize() const { return m_state.size(); }

    std::vector<T> m_block{};
    std::vector<T> m_state{};

private:
    size_t m_counter{};
    size_t m_length{};
    size_t m_digestsize{};
    HashState m_phase{};
};
}

#endif
