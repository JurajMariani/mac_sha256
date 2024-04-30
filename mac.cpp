#include "mac.hpp"
#include <cstdio>
#include <cstring>

MAC::MAC()
{
    for (uint16_t i = 0; i < WORDS_IN_DIGEST * WB; i++) {
        this->passwd[i] = 0;
        ((uint8_t*)(this->mess_auth_code))[i] = 0;
    }
    this->passwd_len = 0;
}

MAC::~MAC()
{
    // Nothing to destroy
}

void MAC::print_mac()
{
    for (uint8_t i = 0; i < WORDS_IN_DIGEST; i++) {
        printf("%08x", this->mess_auth_code[i]);
    }
    printf("\n");
}

void MAC::calculate_mac()
{
    // Setting the initial hash value
    this->initialize_hash();
    // Copy password in before the message
    this->seed_block(this->passwd, this->passwd_len, 1);
    bool res = this->get_block((WORDS_IN_BLOCK * WB) - this->passwd_len);
    while (res || this->aux_exists()) {
        // If no block has been read copy the contents of AUX array to main block
        if (!res)
            this->swap_aux_buff();

        this->sha256round();
        res = this->get_block();
    }
    std::memcpy(this->mess_auth_code, this->getHash(true), WORDS_IN_DIGEST * WB);
}

void MAC::setPasswd(const char* passwd, const uint32_t length)
{
    this->setPasswd((uint8_t*)passwd, length);
}

void MAC::setPasswd(const uint8_t* passwd, const uint32_t length)
{
    this->memcpy_w_endianness(this->passwd, passwd, length, 1);
    this->passwd_len = length;
}

const WORD* MAC::getMAC(const bool old_mac)
{
    if (!old_mac)
        this->calculate_mac();
    return this->mess_auth_code;
}

void MAC::mac(const bool old_mac)
{
    if (!old_mac)
        this->calculate_mac();
    this->print_mac();
}

bool MAC::verify(const WORD* mac, const uint8_t elem_bytes, const uint8_t* passwd)
{
    this->setPasswd(passwd, (uint32_t)strlen((char*)passwd));
    return this->verify(mac, elem_bytes);
}

bool MAC::verify(const WORD* mac, const uint8_t elem_bytes, const char* passwd)
{
    this->setPasswd((uint8_t*)passwd, (uint32_t)strlen(passwd));
    return this->verify(mac, elem_bytes);
}

bool MAC::verify(const WORD* mac, const uint8_t elem_bytes)
{
    // Correct input form
    uint8_t* correct_format_mac[WORDS_IN_DIGEST * WB] = { 0 };
    // If mac is not in DWORD form - transform to DWORD
    if (elem_bytes != WB)
        this->memcpy_w_endianness(correct_format_mac, mac, WORDS_IN_DIGEST * WB, WB);
    else
        std::memcpy(correct_format_mac, mac, WORDS_IN_DIGEST * WB);
    this->calculate_mac();
    return strncmp((char*)correct_format_mac, (char*)(this->mess_auth_code), WORDS_IN_DIGEST * WB);
}
