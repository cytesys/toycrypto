#include <toycrypto/internal/hashbase.h>

template<HBC T, size_t BS, bool BE>
HBase<T, BS, BE>::~HBase() = default;

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::reset() {
    init_state();

    if (get_digestsize() <= 0)
        throw std::invalid_argument("Digest size must be initialized!");

    if (m_state.size() <= 0)
        throw std::invalid_argument("The internal state must be initialized!");

    if (m_rate == 0)
        set_rate(BS * sizeof(T));
    clear_block();
    clear_counter();
    clear_length();
    set_phase(HASH_INIT);
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::update(const char* const _buffer, const size_t buflen) {
    size_t offset = 0;
    const unsigned char* buffer = reinterpret_cast<const unsigned char*>(_buffer);

    if (get_phase() > HASH_UPDATE)
        throw std::invalid_argument("Cannot update after final block");

    set_phase(HASH_UPDATE);

    // Copy bytes from buffer into m_block and process it if it's is full.
    while (offset < buflen) {
        if (get_counter() % get_blocksize_bytes() == 0 && get_length() > 0) {
            process_block();
            clear_counter();
        }

        if constexpr (BE) {
            // Big endian
            m_block.at(get_index()) |= ror_be<T>(buffer[offset], get_counter());
        } else {
            // Little endian
            m_block.at(get_index()) |= rol_le<T>(buffer[offset], get_counter());
        }

        offset++;
        inc_length();
        inc_counter();
    }
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::digest(unsigned char* const output, const size_t outlen) {
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
            *(output + i) = rol_be<T>(m_state.at(i / sizeof(T)), i) & 0xff;
        } else {
            // Little endian
            *(output + i) = ror_le<T>(m_state.at(i / sizeof(T)), i) & 0xff;
        }

        if ((i + 1) % get_blocksize_bytes() == 0)
            process_block();
    }
}

template<HBC T, size_t BS, bool BE>
std::string HBase<T, BS, BE>::hexdigest() {
    std::string result{};

    unsigned char* buffer = reinterpret_cast<unsigned char*>(
        calloc(get_digestsize(), sizeof(unsigned char))
        );
    digest(buffer, get_digestsize());
    result = TC::hexdigest(buffer, get_digestsize());
    free(buffer);
    return result;
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::pad_md(uint8_t byte) {
    if (get_phase() >= HASH_FINAL)
        throw std::invalid_argument("Cannot pad after final block");

    if (get_length() > 0 && get_counter() == get_blocksize_bytes()) {
        process_block();
        clear_counter();
        set_phase(HASH_LAST);
    }

    // Append a padding bit
    if constexpr (BE) {
        // Big endian
        m_block.at(get_index()) |= ror_be<T>(byte, get_counter());
    } else {
        // Little endian
        m_block.at(get_index()) |= rol_le<T>(byte, get_counter());
    }

    inc_counter();
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::pad_md() {
    pad_md(0x80);
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::pad_haifa() {
    /*Append a padding bit at the end of the last
        message byte. */
    pad_md();

    if (get_counter() + (sizeof(T) << 1) > get_blocksize_bytes()) {
        process_block();
        clear_counter();
    }

    /* Padding in HAIFA construction (I think) also appends a bit
        right before the message length. */
    m_block.at(BS - 3) |= 1; // See note below
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::append_length() {
    size_t length = get_length_bits();

    if (get_phase() >= HASH_FINAL)
        throw std::invalid_argument("Cannot append length after final block");

    /* NOTE: Every hash function that I've seen that appends a message length
        thus far, has either a 32-bit T or 64-bit T. In both cases the message
        length is effectively put in the last two block "segments" of m_block. */

    // Process the block if the message length don't fit.
    if (get_counter() + (sizeof(T) << 1) > get_blocksize_bytes()) {
        process_block();
        clear_counter();
    }

    if (get_counter() < 2)
        set_phase(HASH_LAST);

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

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::set_digestsize(size_t dsize) {
    if (dsize <= 0)
        throw std::invalid_argument("Digest size cannot be 0!");

    if (get_digestsize() > 0)
        throw std::invalid_argument("Digest size has already been set");

    m_digestsize = dsize;
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::print_block() const {
    fprintf(stderr, "__ m_block __\n");
    for (int i = 0; i < m_block.size(); i++) {
        fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) << 1), (uint64_t)(m_block.at(i)));
        if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

template<HBC T, size_t BS, bool BE>
void HBase<T, BS, BE>::print_state() const {
    fprintf(stderr, "__ m_state __\n");
    for (int i = 0; i < m_state.size(); i++) {
        fprintf(stderr, "%0*" PRIx64 " ", (int)(sizeof(T) << 1), (uint64_t)(m_state.at(i)));
        if ((i + 1) % (16 / sizeof(T)) == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

template class HBase<uint8_t, 16, true>;
template class HBase<uint32_t, 16, true>;
template class HBase<uint32_t, 16, false>;
template class HBase<uint64_t, 16, true>;
template class HBase<uint64_t, 16, false>;
template class HBase<uint64_t, 25, false>;
