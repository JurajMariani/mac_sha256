#include "mac.hpp"
#include <cstdio>

MAC::MAC()
{

}

MAC::~MAC()
{

}

void MAC::print_mac()
{
    for (uint8_t i = 0; i < WORDS_IN_DIGEST; i++) {
        printf("%08x", this->mess_auth_code[i]);
    }
    printf("\n");
}

bool MAC::setMessage(uint8_t* msg, uint32_t length)
{

}

bool MAC::setPasswd(uint8_t* passwd, uint32_t length)
{

}

const WORD* MAC::getMAC(bool old_mac)
{
    if (!old_mac)
        this->calculate_mac();
    return this->mess_auth_code;
}

void MAC::mac(bool old_mac)
{
    if (!old_mac)
        this->calculate_mac();
    this->print_mac();
}
