#include <span>

#include <toycrypto/internal/hashbase.h>

template<UTYPE T, bool BE>
HBase<T, BE>::HBase(size_t blocksize, size_t rate)
    : m_blocksize(blocksize)
    , m_rate((rate == 0) ? blocksize * sizeof(T) : rate)
{
    if (m_blocksize <= 0)
        throw std::invalid_argument("Blocksize must be more than 0");

    if (m_rate <= 0)
        throw std::invalid_argument("Rate must be more than 0");
}

template<UTYPE T, bool BE>
void HBase<T, BE>::reset() {
    // Defaults
    m_block.assign(m_blocksize, 0);
    clear_counter();
    clear_length();
    m_final_is_pad = false;

    reset_subclass();

    if (get_digestsize() <= 0)
        throw std::invalid_argument("The digest size must be initialized!");

    if (m_state.empty())
        throw std::invalid_argument("The internal state must be initialized!");

    set_enum(HASH_INIT);
}

template<UTYPE T, bool BE>
void HBase<T, BE>::set_digestsize(size_t dsize) {
    if (dsize <= 0)
        throw std::invalid_argument("The digest size must be more than 0");

    if (get_digestsize() > 0)
        throw std::invalid_argument("The digest size has already been set");

    m_digestsize = dsize;
}

template<UTYPE T, bool BE>
void HBase<T, BE>::_print_vec(const std::vector<T> &vec, const std::string& vecname) {
    fprintf(stderr, "__ %s __\n", vecname.c_str());
    for (int i = 0; i < vec.size(); i++) {
        fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) << 1), (uint64_t)(vec[i]));
        if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

template<UTYPE T, bool BE>
void HBase<T, BE>::update(const char* const buffer, const size_t buflen) {
    if (get_enum() < HASH_INIT)
        throw std::invalid_argument("Cannot update; not initialized");

    if (get_enum() > HASH_UPDATE)
        throw std::invalid_argument("Cannot update after final block");

    set_enum(HASH_UPDATE);

    auto sp = std::span(reinterpret_cast<const unsigned char*>(buffer), buflen);

    // Copy bytes from buffer into m_block and process it if it's is full.
    for (T c : sp) {
        if (get_length() > 0 && get_counter() == get_rate()) {
            process_block();
            clear_counter();
        }

        if constexpr (sizeof(T) == 1) {
            // T is just one byte, so rotating is unecessary.
            m_block[get_counter()] = c;
        } else if constexpr (BE) {
            // Big endian
            m_block[get_index()] |= ror_be(c, get_counter());
        } else {
            // Little endian
            m_block[get_index()] |= rol_le(c, get_counter());
        }

        inc_length();
        inc_counter();
    }
}

template<UTYPE T, bool BE>
void HBase<T, BE>::digest(unsigned char* const output, const size_t outlen) {
    if (get_enum() < HASH_INIT)
        throw std::invalid_argument("Cannot digest; not initialized");

    if (get_enum() < HASH_FINAL)
        throw std::invalid_argument("Cannot digest before final block");

    const size_t dsize = (get_xof()) ? outlen : get_digestsize();

    if (dsize <= 0 || outlen < dsize)
        throw std::invalid_argument("The output buffer size is too small");

    set_enum(HASH_DIGEST);

    auto sp = std::span(output, outlen);
    size_t offset = 0;

    // Copy every byte from the state to the output buffer
    for (unsigned char& c : sp) {
        if (get_xof()) {
            // Process an empty block when we hit rate
            if (offset % get_rate() == 0 && offset > 0) {
                process_block();
                offset = 0;
            }
        }

        if constexpr (sizeof(T) == 1) {
            // T is just 1 byte, so rotating is unnecessary.
            c = m_state[offset];
        } else if constexpr (BE) {
            // Big endian
            c = rol_be<T>(m_state[offset / sizeof(T)], offset) & 0xff;
        } else {
            // Little endian
            c = ror_le<T>(m_state[offset / sizeof(T)], offset) & 0xff;
        }
        offset++;
    }
}

template<UTYPE T, bool BE>
std::string HBase<T, BE>::hexdigest(size_t len) {
    if (get_xof() && len <= 0)
        throw std::invalid_argument("Hexdigest: a length is required in XOF hash functions.");

    std::string result{};
    const size_t length = (get_xof()) ? len : get_digestsize();
    auto *buffer = reinterpret_cast<unsigned char*>(
        calloc(length, sizeof(unsigned char))
    );

    digest(buffer, length);
    result = TC::hexdigest(buffer, length);
    free(buffer);
    return result;
}

template<UTYPE T, bool BE>
void HBase<T, BE>::pad_byte(uint8_t byte) {
    if (get_enum() < HASH_INIT)
        throw std::invalid_argument("Cannot pad: not initialized");

    if (get_enum() > HASH_FINAL)
        throw std::invalid_argument("Cannot pad after final block");

    if (get_length() > 0 && get_counter() == get_rate()) {
        // The last block was full
        process_block();
        clear_counter();
    }

    // Append a padding bit
    if constexpr (BE) {
        // Big endian
        m_block[get_index()] |= ror_be<T>(byte, get_counter());
    } else {
        // Little endian
        m_block[get_index()] |= rol_le<T>(byte, get_counter());
    }

    inc_counter();
}

template<UTYPE T, bool BE>
void HBase<T, BE>::pad_haifa() {
    pad_md();

    if (get_counter() + (sizeof(T) << 1) > get_rate()) {
        process_block();
        clear_counter();
    }

    /* Padding in HAIFA construction (I think) also appends a bit
        right before the message length. */
    m_block[(get_rate() / sizeof(T)) - 3] |= 1;
}

template<UTYPE T, bool BE>
void HBase<T, BE>::append_length() {
    /* NOTE: Every hash function that I've seen that appends a message length
        thus far, has either a 32-bit T or 64-bit T. In both cases the message
        length is effectively put in the last two block "segments" of m_block. */
    if constexpr (sizeof(T) != 4 && sizeof(T) != 8)
        throw std::runtime_error("Append_length is not implemented for this bitwidth");

    if (get_enum() < HASH_INIT)
        throw std::invalid_argument("Cannot append length; not initialized");

    if (get_enum() > HASH_FINAL)
        throw std::invalid_argument("Cannot append length after final block");

    // Process the block if the message length don't fit.
    if (get_counter() + (sizeof(T) << 1) > get_rate()) {
        process_block();
        clear_counter();
    }

    if (get_counter() < 2)
        set_final_pad();

    const size_t length = get_length_bits();

    // Append the message length in bits
    if constexpr (BE) {
        m_block[m_blocksize - 1] = (T)length;
        if constexpr (sizeof(T) == 4) // See the note above
            m_block[m_blocksize - 2] = (T)(length >> 32);
    } else {
        m_block[m_blocksize - 2] = (T)length;
        if constexpr (sizeof(T) == 4) // See the note above
            m_block[m_blocksize - 1] = (T)(length >> 32);
    }

    set_enum(HASH_FINAL);
    process_block();
}

template class HBase<uint8_t, true>;
template class HBase<uint32_t, true>;
template class HBase<uint32_t, false>;
template class HBase<uint64_t, true>;
template class HBase<uint64_t, false>;
