#ifndef __MAC_SHA256_xmaria03__
#define __MAC_SHA256_xmaria03__

#include "sha256.hpp"
#include "defs.hpp"

class MAC : public SHA256 {
    private:
        uint8_t passwd[WORDS_IN_DIGEST * WB];
        uint8_t passwd_len;
        WORD mess_auth_code[WORDS_IN_DIGEST];

    protected:
        void print_mac();
        void calculate_mac();

    public:
        MAC();
        ~MAC();
        const WORD* getMAC(const bool old_mac = false);
        void mac(const bool old_mac = false);
        void setPasswd(const uint8_t* passwd, const uint32_t length);
        void setPasswd(const char* passwd, const uint32_t length);
        bool verify(const WORD* mac, const uint8_t elem_bytes, const uint8_t* passwd);
        bool verify(const WORD* mac, const uint8_t elem_bytes, const char* passwd);
        bool verify(const WORD* mac, const uint8_t elem_bytes);
};

#endif
