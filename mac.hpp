#ifndef __MAC_SHA256_xmaria03__
#define __MAC_SHA256_xmaria03__

#include "sha256.hpp"
#include "defs.hpp"

class MAC : protected SHA256 {
    private:
        uint8_t message[BLOCK_SIZEB];
        uint8_t passwd[BLOCK_SIZEB];
        WORD mess_auth_code[WORDS_IN_DIGEST];

    protected:
        void print_mac();
        void calculate_mac();

    public:
        MAC();
        ~MAC();
        const WORD* getMAC(bool old_mac = false);
        void mac(bool old_mac = false);
        bool setMessage(uint8_t* msg, uint32_t length);
        bool setPasswd(uint8_t* passwd, uint32_t length);
};

#endif