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
concept HBC = std::is_integral<T>::value;

template<HBC T, size_t BS, bool BE>
class HBase {
public:
    virtual ~HBase() = 0;

    TC_API virtual void reset() {
        init_state();

        if (m_digestsize <= 0)
            throw std::invalid_argument("Digest size must be initialized!");

        if (m_state.size() <= 0)
            throw std::invalid_argument("The internal state must be initialized!");

        m_block.assign(BS, 0);
        m_counter = 0;
        m_length = 0;
        m_phase = HASH_INIT;
    }

    TC_API void update(const char* buffer, size_t buflen) {
        if (m_phase > HASH_UPDATE)
            throw std::invalid_argument("Cannot update after final block");

        m_phase = HASH_UPDATE;

        size_t offset = 0;

        // Copy bytes from buffer into m_block and process it if it's is full.
        while (offset < buflen) {
            if constexpr (BE) {
                // Big endian
                m_block.at(m_counter / sizeof(T)) ^= H_ROR_BE((T)(buffer[offset]), m_counter);
            } else {
                // Little endian
                m_block.at(m_counter / sizeof(T)) ^= H_ROL_LE((T)(buffer[offset]), m_counter);
            }

            offset++;
            m_length++;
            if ((++m_counter % (BS * sizeof(T))) == 0) {
                m_counter += BS;
                process_block();
                m_counter = 0;
            }
        }
    }

    virtual void finalize() = 0;

    TC_API void digest(unsigned char* output, size_t outlen) {
        if (m_phase < HASH_FINAL)
            throw std::invalid_argument("Cannot digest before final block");

        if (outlen < m_digestsize)
            throw std::invalid_argument("Output buffer size is too small");

        m_phase = HASH_DIGEST;

        // Copy every byte fro m_state to output
        for (unsigned i = 0; i < m_digestsize; i++) {
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
        unsigned char* buffer = reinterpret_cast<unsigned char*>(
            calloc(m_digestsize, sizeof(unsigned char))
            );
        digest(buffer, m_digestsize);
        std::string result = TC::hexdigest(buffer, m_digestsize);
        free(buffer);
        return result;
    }

    TC_API size_t digestsize() {
        return m_digestsize;
    }

protected:
    virtual void init_state() = 0;
    virtual void process_block() = 0;

    void pad_md() {
        if (m_phase >= HASH_FINAL)
            throw std::invalid_argument("Cannot pad after final block");

        // Append a padding bit
        if constexpr (BE) {
            // Big endian
            m_block.at(m_counter / sizeof(T)) ^= H_ROR_BE((T)0x80, m_counter);
        } else {
            // Little endian
            m_block.at(m_counter / sizeof(T)) ^= H_ROL_LE((T)0x80, m_counter);
        }
    }

    void pad_haifa() {
        /*Append a padding bit at the end of the last
        message byte. */
        pad_md();

        /* Padding in HAIFA construction (I think) also appends a bit
        right before the message length. */
        m_block.at(BS - 3) ^= 1; // See note below
    }

    void append_length() {
        if (m_phase >= HASH_FINAL)
            throw std::invalid_argument("Cannot append length after final block");

        /* NOTE: Every hash function that I've seen that appends a message length
        thus far, has either a 32-bit T or 64-bit T. In both cases the message
        length is effectively put in the last two block "segments" of m_block. */

        // Process the block if the message length don't fit.
        if (m_counter >= BS * sizeof(T) - (sizeof(T) * 2))
            process_block();

        // Append the length in bits
        m_length *= 8;

        // Append the message length
        if constexpr (BE) {
            m_block.at(BS - 1) = (T)m_length;
            if constexpr (sizeof(T) == 4) // See the note above
                m_block.at(BS - 2) = (T)(m_length >> 32);
        } else {
            m_block.at(BS - 2) = (T)m_length;
            if constexpr (sizeof(T) == 4) // See the note above
                m_block.at(BS - 1) = (T)(m_length >> 32);
        }

        m_phase = HASH_FINAL;
        process_block();
    }

    void set_digestsize(size_t dsize) {
        if (dsize <= 0)
            throw std::invalid_argument("Digest size cannot be 0!");

        if (m_digestsize > 0)
            throw std::invalid_argument("Digest size has already been set");

        m_digestsize = dsize;
    }

    void clear_m_block() {
        m_block.assign(m_block.size(), 0);
    }

    void print_m_block() {
        fprintf(stderr, "__ m_block __\n");
        for (int i = 0; i < m_block.size(); i++) {
            fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) * 2), (uint64_t)(m_block.at(i)));
            if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
    }

    std::vector<T> m_block{};
    std::vector<T> m_state{};
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
}

#endif
