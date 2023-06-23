#pragma once

#ifndef TC_HASHBASE_H
#define TC_HASHBASE_H

#define __STDC_FORMAT_MACROS

#include <concepts>
#include <string>
#include <vector>
#include <stdexcept>
#include <cinttypes>

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/common.h>
#include <toycrypto/hash/hash_common.h>
#include <toycrypto/common/util.h>

#define H_ROT_BE(i) ((((i) + 1) % sizeof(T)) * 8)
#define H_ROT_LE(i) (((i) % sizeof(T)) * 8)

#define H_ROR_BE(d, i) ROR((d), H_ROT_BE(i), sizeof(T) * 8)
#define H_ROR_LE(d, i) ROR((d), H_ROT_LE(i), sizeof(T) * 8)
#define H_ROL_BE(d, i) ROL((d), H_ROT_BE(i), sizeof(T) * 8)
#define H_ROL_LE(d, i) ROL((d), H_ROT_LE(i), sizeof(T) * 8)

extern "C++" {
template<typename T>
concept HBC = std::is_integral<T>::value && std::is_unsigned<T>::value;

template<HBC T, size_t BS, bool BE>
class HBase {
public:
    virtual ~HBase() = 0;

    TC_API virtual void reset() {
        init_state();

        if (get_digestsize() <= 0)
            throw std::invalid_argument("Digest size must be initialized!");

        if (get_statesize() <= 0)
            throw std::invalid_argument("The internal state must be initialized!");

        assign_block();
        clear_counter();
        clear_length();
        set_phase(HASH_INIT);
    }

    TC_API void update(const char* _buffer, size_t buflen) {
        size_t offset = 0;
        const unsigned char* buffer = reinterpret_cast<const unsigned char*>(_buffer);

        if (get_phase() > HASH_UPDATE)
            throw std::invalid_argument("Cannot update after final block");

        set_phase(HASH_UPDATE);

        // Copy bytes from buffer into m_block and process it if it's is full.
        while (offset < buflen) {
            if constexpr (BE) {
                // Big endian
                m_block.at(get_index()) |= H_ROR_BE((T)(buffer[offset]), get_counter());
            } else {
                // Little endian
                m_block.at(get_index()) |= H_ROL_LE((T)(buffer[offset]), get_counter());
            }

            offset++;
            inc_length();
            inc_counter();
            if (get_counter() % get_blocksize_bytes() == 0) {
                process_block();
                clear_counter();
            }
        }
    }

    virtual void finalize() = 0;

    TC_API void digest(unsigned char* output, size_t outlen) {
        unsigned i;

        if (get_phase() < HASH_FINAL)
            throw std::invalid_argument("Cannot digest before final block");

        if (outlen < get_digestsize())
            throw std::invalid_argument("The output buffer size is too small");

        set_phase(HASH_DIGEST);

        // Copy every byte fro m_state to output
        for (i = 0; i < get_digestsize(); i++) {
            if constexpr (BE) {
                // Big endian
                *(output + i) = H_ROL_BE(m_state.at(i / sizeof(T)), i) & 0xff;
            } else {
                // Little endian
                *(output + i) = H_ROR_LE(m_state.at(i / sizeof(T)), i) & 0xff;
            }
        }
    }

    TC_API std::string hexdigest() {
        std::string result{};

        unsigned char* buffer = reinterpret_cast<unsigned char*>(
            calloc(get_digestsize(), sizeof(unsigned char))
        );
        digest(buffer, get_digestsize());
        result = TC::hexdigest(buffer, get_digestsize());
        free(buffer);
        return result;
    }

    TC_API inline size_t get_digestsize() {
        return m_digestsize;
    }

protected:
    virtual void init_state() = 0;
    virtual void process_block() = 0;

    void pad_md() {
        if (get_phase() >= HASH_FINAL)
            throw std::invalid_argument("Cannot pad after final block");

        if (get_length() > 0 && get_counter() == 0) {
            set_phase(HASH_LAST);
        }

        // Append a padding bit
        if constexpr (BE) {
            // Big endian
            m_block.at(get_index()) |= H_ROR_BE((T)0x80u, get_counter());
        } else {
            // Little endian
            m_block.at(get_index()) |= H_ROL_LE((T)0x80u, get_counter());
        }

        if (get_counter() + (sizeof(T) << 1) >= get_blocksize_bytes()) {
            process_block();
            clear_counter();
            set_phase(HASH_LAST);
        }
    }

    void pad_haifa() {
        /*Append a padding bit at the end of the last
        message byte. */
        pad_md();

        if (get_counter() + (sizeof(T) << 1) >= get_blocksize_bytes()) {
            process_block();
            clear_counter();
        }

        /* Padding in HAIFA construction (I think) also appends a bit
        right before the message length. */
        m_block.at(BS - 3) |= 1; // See note below
    }

    void append_length() {
        size_t length = get_length_bits();

        if (get_phase() >= HASH_FINAL)
            throw std::invalid_argument("Cannot append length after final block");

        /* NOTE: Every hash function that I've seen that appends a message length
        thus far, has either a 32-bit T or 64-bit T. In both cases the message
        length is effectively put in the last two block "segments" of m_block. */

        // Process the block if the message length don't fit.
        if (get_counter() + (sizeof(T) << 1) >= get_blocksize_bytes()) {
            process_block();
            clear_counter();
        }

        // Append the message length in bits
        if constexpr (BE) {
            m_block.at(BS - 1) = (T)length;
            if constexpr (sizeof(T) == 4) // See the note above
                m_block.at(BS - 2) = (T)(length >> 32);
        } else {
            m_block.at(BS - 2) = (T)length;
            if constexpr (sizeof(T) == 4) // See the note above
                m_block.at(BS - 1) = (T)(length >> 32);
        }

        process_block();
        set_phase(HASH_FINAL);
    }

    void set_digestsize(size_t dsize) {
        if (dsize <= 0)
            throw std::invalid_argument("Digest size cannot be 0!");

        if (get_digestsize() > 0)
            throw std::invalid_argument("Digest size has already been set");

        m_digestsize = dsize;
    }

    void print_block() {
        fprintf(stderr, "__ m_block __\n");
        for (int i = 0; i < get_blocksize(); i++) {
            fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) << 1), (uint64_t)(m_block.at(i)));
            if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }

    void print_state() {
        fprintf(stderr, "__ m_state __\n");
        for (int i = 0; i < get_statesize(); i++) {
            fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) << 1), (uint64_t)(m_state.at(i)));
            if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }

    inline void assign_block() { m_block.assign(BS, 0); }

    inline void clear_block() { std::for_each(m_block.begin(), m_block.end(), [](T &b) {b ^= b;}); }

    inline void clear_length() { m_length ^= m_length; }

    inline void inc_length() { m_length++; }

    inline void inc_length(size_t len) { m_length += len; }

    inline void clear_counter() { m_counter ^= m_counter; }

    inline void inc_counter() { m_counter++; }

    inline void inc_counter(size_t len) { m_counter += len; }

    inline size_t get_length() { return m_length; }

    inline size_t get_length_bits() { return m_length << 3; }

    inline size_t get_counter() { return m_counter; }

    inline size_t get_index() { return m_counter / sizeof(T); }

    inline HashState get_phase() { return m_phase; }

    inline void set_phase(HashState phase) { m_phase = phase; }

    inline size_t get_blocksize() { return m_block.size(); }

    inline size_t get_blocksize_bytes() { return m_block.size() * sizeof(T); }

    inline size_t get_blocksize_bits() { return get_blocksize_bytes() << 3; }

    inline size_t get_statesize() { return m_state.size(); }

    std::vector<T> m_block{};
    std::vector<T> m_state{};

private:
    size_t m_counter{};
    size_t m_length{};
    size_t m_digestsize{};
    HashState m_phase{};
};

template<HBC T, size_t BS, bool BE>
HBase<T, BS, BE>::~HBase() {}

template class HBase<uint8_t, 16, true>;
template class HBase<uint32_t, 16, true>;
template class HBase<uint32_t, 16, false>;
template class HBase<uint64_t, 16, true>;
template class HBase<uint64_t, 16, false>;
}

#endif
