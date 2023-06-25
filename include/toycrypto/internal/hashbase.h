#pragma once

#ifndef TC_HASHBASE_H
#define TC_HASHBASE_H

#define __STDC_FORMAT_MACROS

#include <toycrypto/internal/headerstuff.h>
#include <toycrypto/internal/common.h>
#include <toycrypto/hash/hash_common.h>
#include <toycrypto/common/util.h>

extern "C++" {

template<UTYPE T, bool BE>
class HBase : public HashAPI {
public:
    // CTor
    TC_API HBase(size_t blocksize, size_t rate = 0);

    // Resets this HBase instance and calls reset_subclass().
    TC_API void reset() final;

    // Updates the block data.
    TC_API void update(const char* _buffer, size_t buflen) final;

    // "Outputs" a digest.
    TC_API void digest(unsigned char* output, size_t outlen = 0) final;

    // Outputs a hexdigest.
    TC_API std::string hexdigest(size_t len = 0) final;

    // Returns the digest size in bytes.
    TC_API inline size_t get_digestsize() const { return m_digestsize; }

protected:
    // Resets a subclass. Must be implemented in the subclass itself.
    virtual void reset_subclass() = 0;

    // Processes one block. Must be implemented in a subclass.
    virtual void process_block() = 0;

    // Pads the block with any byte.
    void pad_byte(uint8_t byte);

    // Pads the block with Merkle Dammgård style padding.
    void pad_md() { pad_byte(0x80); }

    // Pads the block with HAIFA style padding.
    void pad_haifa();

    // Appends the message length at the end of the block.
    void append_length();

    // Sets the digest size in bytes.
    void set_digestsize(size_t dsize);

    // Prints the contents of the block.
    inline void print_block() const { _print_vec(m_block, "Block"); }

    // Prints the contents of the internal state.
    inline void print_state() const { _print_vec(m_state, "State"); }

    // Prints the contents of the working vector.
    inline void print_tmp() const { _print_vec(m_tmp, "Tmp"); }

    // Fills the block with 0's.
    inline void clear_block() { _clear_vec(m_block); }

    // Fills the internal state with 0's.
    inline void clear_state() { _clear_vec(m_state); }

    // Fills the working vector with 0's.
    inline void clear_tmp() { _clear_vec(m_tmp); }

    // Returns the current message length in bytes.
    inline size_t get_length() const { return m_length; }

    // Returns the current message length in bits.
    inline size_t get_length_bits() const { return m_length << 3; }

    // Sets the message length to 0.
    inline void clear_length() { m_length = 0; }

    // Increases the message length by 1.
    inline void inc_length() { m_length++; }

    // Increases the message length by len.
    inline void inc_length(size_t len) { m_length += len; }

    // Returns true if this hash function has an XOF.
    inline bool get_xof() const { return m_xof; }

    // Specifies that this hash function should have an XOF.
    inline void set_xof() { m_xof = true; }

    // Returns the current status of this hash function.
    inline HashEnum get_enum() const { return m_status; }

    // Sets the current status of this hash function.
    inline void set_enum(HashEnum status) { m_status = status; }

    // Sets the internal counter to 0.
    inline void clear_counter() { m_counter = 0; }

    // Increases the internal counter by 1.
    inline void inc_counter() { m_counter++; }

    // Increases the internal counter by len.
    inline void inc_counter(size_t len) { m_counter += len; }

    // Returns the current internal counter.
    inline size_t get_counter() const { return m_counter; }

    // Returns the current block index.
    inline size_t get_index() const { return m_counter / sizeof(T); }

    // Returns the block rate in bytes.
    inline size_t get_rate() const { return m_rate; }

    // Returns the
    inline bool get_final_pad() const { return m_final_is_pad; }

    inline void set_final_pad() { m_final_is_pad = true; }

    std::vector<T> m_block{}; // The block.
    std::vector<T> m_state{}; // The internal state.
    std::vector<T> m_tmp{}; // The working vector.

private:
    // Prints the contents of a vector.
    static void _print_vec(const std::vector<T>&, const std::string&);

    // Fills a vector with 0's.
    inline static void _clear_vec(std::vector<T> &vec) { vec.assign(vec.size(), 0); }

    size_t m_counter = 0;
    size_t m_length = 0;
    size_t m_digestsize = 0;
    HashEnum m_status = HASH_NOT_READY;
    bool m_xof = false;
    bool m_final_is_pad = false;

    const size_t m_blocksize;
    const size_t m_rate;
};
}

#endif
