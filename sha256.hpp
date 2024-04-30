#ifndef __SHA256_xmaria03__
#define __SHA256_xmaria03__

#include <cstdint>
#include "defs.hpp"

class SHA256 {
    private:
        uint8_t buff_block[WORDS_IN_BLOCK * WB];
        uint8_t* auxiliary_padding_block;
        uint8_t buff_block_len;
        uint64_t content_len;
        WORD message_schedule[SCHEDULE_SIZE];
        WORD digest[WORDS_IN_DIGEST];
        WORD initial_hash[WORDS_IN_DIGEST] = INIT_HASH;
        bool fst_read = true;
        bool little_endian;
        bool seeded = false;

    protected:
        void memcpy_w_endianness(void* dst, const void* src, uint64_t byte_size, uint8_t dst_bytes);
        bool get_block(const uint16_t byte_size = (WORDS_IN_BLOCK * WB));
        void pad_message();
        void recompute_schedule();
        void recompute_hash(WORD wv[WORKING_VAR_CNT]);
        void sha256round();
        void sha256sum();
        void print_hash();
        void initialize_hash();
        bool aux_exists();
        void swap_aux_buff();
        void seed_block(const void* seed, const uint32_t byte_length, const uint8_t elem_byte_size = 1);

    public:
        SHA256();
        ~SHA256();
        const WORD* getHash(bool old_hash = false);
        void hash(bool old_hash = false);
        void __set_init_hash(const void* i_hash = init_hash, uint8_t elem_size = 1);
};

#endif
