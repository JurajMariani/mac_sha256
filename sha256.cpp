#include <iostream>
#include <cstdlib>
#include <cstring>
#include "sha256.hpp"

void SHA256::memcpy_w_endianness(void* dst, void* src, uint64_t byte_size, uint8_t dst_bytes)
{
    if (this->little_endian) {
        for (uint64_t i = 0; i < byte_size; i += dst_bytes) {
            for (int16_t j = dst_bytes - 1; j >= 0; j--) {
                ((uint8_t*)dst)[i + (dst_bytes - j - 1)] = ((uint8_t*)src)[i + j];
            }
        }
    } else {
        memcpy(dst, src, byte_size);
    }
    
}

void SHA256::pad_message()
{
    // Calculate the number of zeros to end of block
    int remain_zeros = PAD_LEN_MOD - (((this->buff_block_len * 8) + 1) % BLOCK_SIZE);
    // Normal scenario => pad with zeros and add length
    uint8_t end = 0;
    if (remain_zeros >= 0)
        end = (WORDS_IN_BLOCK - 2) * WB;
    else
        end = BLOCK_SIZEB;

    for (uint8_t i = this->buff_block_len; i < end; i++) {
        // Insert padding
        // In the first iteration, add the leading 1 bit
        if (i == this->buff_block_len)
            this->buff_block[i] = 0x80;
        else
            this->buff_block[i] = 0x00;
    }

    if (remain_zeros >= 0) {
        for (uint8_t i = (WORDS_IN_BLOCK - 2) * WB; i < BLOCK_SIZEB; i++) {
            this->buff_block[i] = ((this->content_len * 8) >> (BLOCK_SIZEB - i - 1) * 8) & 0xff;
        }
    } else {
        // Abnormal scenario => a new block needs to be created
        this->auxiliary_padding_block = (uint8_t*)malloc(WORDS_IN_BLOCK * WB);
        if (!this->auxiliary_padding_block) {
            std::cerr << "ERROR: MEMALLOC failed." << std::endl;
            return;
        }

        // Fill the aux array with all zeros
        for (uint8_t i = 0; i < ((WORDS_IN_BLOCK - 2) * WB); i++)
            this->auxiliary_padding_block[i] = 0x00;
        // Add the content length to the end of aux block
        for (uint8_t i = (WORDS_IN_BLOCK - 2) * WB; i < BLOCK_SIZEB; i++) {
            this->auxiliary_padding_block[i] = ((this->content_len * 8) >> (BLOCK_SIZEB - i - 1) * 8) & 0xff;
        }
    }
}

bool SHA256::get_block()
{
    uint8_t n_read = fread(this->buff_block, 1, WORDS_IN_BLOCK * WB, stdin);
    this->content_len += n_read;
    if (!n_read) {
        if (this->fst_read) {
            this->fst_read = false;
            this->buff_block_len = 0;
            this->pad_message();
            return true;
        }
        // Nothing read => return failure
        return false;
    } else {
        this->buff_block_len = n_read;
        if (this->fst_read)
            this->fst_read = false;
        if (n_read < (WORDS_IN_BLOCK * WB)) {
            // Pad the block first
            this->pad_message();
        }
        return true;
    }
}

void SHA256::recompute_schedule()
{
    // The first 16 Words consist of the message
    this->memcpy_w_endianness(this->message_schedule, this->buff_block, WORDS_IN_BLOCK * WB, WB);
    // The next Words are calculated in compliance with the standard
    for (uint8_t t = WORDS_IN_BLOCK; t < SCHEDULE_SIZE; t++) {
        this->message_schedule[t] = ADD(SIG1(this->message_schedule[t-2]), this->message_schedule[t-7]);
        this->message_schedule[t] = ADD(this->message_schedule[t], SIG0(this->message_schedule[t-15]));
        this->message_schedule[t] = ADD(this->message_schedule[t], this->message_schedule[t-16]);
    }
}

void SHA256::recompute_hash(WORD wv[WORKING_VAR_CNT])
{
    for (uint8_t i = 0; i < WORDS_IN_DIGEST; i++)
        this->digest[i] = ADD(wv[i], this->digest[i]);
}

int SHA256::sha256sum()
{
    // Setting the initial hash value
    std::memcpy(this->digest, init_hash, W);
    this->content_len = 0;
    // In case of sha256 these are the a-h variables
    WORD working_vars[WORKING_VAR_CNT] = {0};
    WORD T1 = 0;
    WORD T2 = 0;

    uint64_t message_index = 0;
    bool res = this->get_block();
    while (res || this->auxiliary_padding_block) {
        // If no block has been read copy the contents of AUX array to main block
        if (!res) {
            std::memcpy(this->buff_block, this->auxiliary_padding_block, BLOCK_SIZEB);
            free(this->auxiliary_padding_block);
            this->auxiliary_padding_block = (uint8_t*)nullptr;
        }

        this->recompute_schedule();
        // Copy previous hash value to working variables
        std::memcpy(working_vars, this->digest, WORDS_IN_DIGEST * WB);

        for (int t = 0; t < SCHEDULE_SIZE; t++) {
            T1 = ADD(working_vars[working_names::h], SUM1(working_vars[working_names::e]));
            T1 = ADD(T1, CH(working_vars[working_names::e], working_vars[working_names::f], working_vars[working_names::g]));
            T1 = ADD(T1, k[t]);
            T1 = ADD(T1, this->message_schedule[t]);

            T2 = ADD(SUM0(working_vars[working_names::a]), MAJ(working_vars[working_names::a], working_vars[working_names::b], working_vars[working_names::c]));

            working_vars[working_names::h] = working_vars[working_names::g];
            working_vars[working_names::g] = working_vars[working_names::f];
            working_vars[working_names::f] = working_vars[working_names::e];
            working_vars[working_names::e] = ADD(working_vars[working_names::d], T1);
            working_vars[working_names::d] = working_vars[working_names::c];
            working_vars[working_names::c] = working_vars[working_names::b];
            working_vars[working_names::b] = working_vars[working_names::a];
            working_vars[working_names::a] = ADD(T1, T2);
        }
        this->recompute_hash(working_vars);
        message_index++;
        res = this->get_block();
    }
    return 0;
}

void SHA256::print_hash()
{
    for (uint8_t i = 0; i < WORDS_IN_DIGEST; i++) {
        printf("%08x", this->digest[i]);
    }
    printf("\n");
}

SHA256::SHA256()
{
    uint32_t num = 1;
    this->little_endian = (*(uint8_t*)&num == 1);
    this->auxiliary_padding_block = (uint8_t*)0;
    this->buff_block_len = 0;
    this->content_len = 0;
}

SHA256::~SHA256()
{
    if (this->auxiliary_padding_block)
        free(this->auxiliary_padding_block);
    this->auxiliary_padding_block = (uint8_t*)0;
    this->buff_block_len = 0;
    this->content_len = 0;
}

const WORD* SHA256::getHash(bool old_hash)
{
    if (!old_hash)
        this->sha256sum();
    return (this->digest);
}

void SHA256::hash(bool old_hash)
{
    if (!old_hash)
        this->sha256sum();
    this->print_hash();
}