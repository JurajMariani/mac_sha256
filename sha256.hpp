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
        WORD digest[WORDS_IN_DIGEST] = INIT_HASH;
        bool fst_read = true;
        bool little_endian;

    protected:
        void memcpy_w_endianness(void* dst, void* src, uint64_t byte_size, uint8_t dst_bytes);
        bool get_block();
        void pad_message();
        void recompute_schedule();
        void recompute_hash(WORD wv[WORKING_VAR_CNT]);
        int sha256sum();
        void print_hash();

    public:
        SHA256();
        ~SHA256();
        const WORD* getHash(bool old_hash = false);
        void hash(bool old_hash = false);
};

#endif
