#include "mac.hpp"
#include <cstring>
#include <iostream>

enum mandatory_args {mc, ms, mv, me, err};
enum supplementary_args {sk, sm, sn, sa};

/**
 * @brief To determine length of input and storage of last 56 Bytes
 * 
 * @param ret Empty address -> 64 Bytes <=> 512 bits
 * @return uint64_t* number of elements read
 */
uint64_t read_stdin(uint8_t** ret)
{
    (*ret) = (uint8_t*) malloc(WORDS_IN_BLOCK * WB);
    if (!(*ret))
        return UINT16_MAX;
    uint64_t input_len = 0;
    uint8_t idx = 0;
    // Set array to zeros
    for (idx = 0; idx < WORDS_IN_BLOCK * WB; idx++) {
        (*ret)[idx] = 0;
    }
    int16_t inpt = getchar();
    for (idx = 0; inpt != EOF; idx++) {
        if (idx >= ((WORDS_IN_BLOCK - 2) * WB) - 1) {
            // Potentially shift array one element to the left if input size is greater than 56 characters
            for (uint8_t i = 1; i < ((WORDS_IN_BLOCK - 2) * WB) - 1; i++) {
                (*ret)[i - 1] = (*ret)[i];
            }
            idx -= 1;
        }
        (*ret)[idx] = inpt;
        input_len++;
        inpt = getchar();
    }
    return input_len;
}

/**
 * @brief Add padding to arr
 * 
 * @param arr Array
 * @param start Start index
 * @param end End of array (not end index!!!)
 */
void pad(void** arr, uint16_t start, uint16_t end)
{
    if (start > end)
        return;
    for (uint16_t x = start; x < end; x++) {
        if (x == start)
            ((uint8_t*)(*arr))[x] = 0x80;
        else
            ((uint8_t*)(*arr))[x] = 0x00;
    }
}

/**
 * @brief Print in mandatory format
 * *USED FOR LEA*
 * @param message ...
 * @param extension ...
 */
void pretty_print(uint8_t* message, uint8_t* extension)
{
    for (uint8_t i = 0; i < (WORDS_IN_BLOCK - 2) * WB; i++) {
        if ((message[i] >= '!') && (message[i] <= '~'))
            printf("%c", message[i]);
        else
            printf("\\x%02x", message[i]);
    }
    for (uint8_t i = (WORDS_IN_BLOCK - 2) * WB; i < BLOCK_SIZEB; i++)
        printf("\\x%02x", message[i]);
    for (uint8_t i = 0; i < strlen((char*)extension); i++)
        printf("%c", extension[i]);
    printf("\n");
}

/**
 * @brief Sweep through ARGV for main arguments
 * *SEE HELP MSG*
 * 
 * @param argc ...
 * @param argv ...
 * @return mandatory_args(enum) 
 */
mandatory_args initial_sweep(const int argc, const char** argv)
{
    mandatory_args ret = mandatory_args::err;
    bool only_one = true;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c")) {
            if (!only_one)
                return mandatory_args::err;
            only_one = false;
            ret = mandatory_args::mc;
            continue;
        }
        if (!strcmp(argv[i], "-s")) {
            if (!only_one)
                return mandatory_args::err;
            only_one = false;
            ret = mandatory_args::ms;
            continue;
        }
        if (!strcmp(argv[i], "-v")) {
            if (!only_one)
                return mandatory_args::err;
            only_one = false;
            ret = mandatory_args::mv;
            continue;
        }
        if (!strcmp(argv[i], "-e")) {
            if (!only_one)
                return mandatory_args::err;
            only_one = false;
            ret = mandatory_args::me;
            continue;
        } 
    }
    return ret;
}

/**
 * @brief Find Needle in a Haystack
 * 
 * @param haystack Arr
 * @param argc Element count within haystack
 * @param needle 
 * @return Status (found)
 */
int find_supplementary(const char** haystack, const int argc, const char* needle)
{
    for (uint16_t i = 1; i < argc; i++) {
        if (!strcmp(haystack[i], needle)) {
            if ((i + 1) < argc)
                return (i + 1);
            else
                return -1;
        }
    }
    return -1;
}

/**
 * @brief Used to transform argv string to MAC
 * 
 * @param src argv string
 * @return uint8_t* Allocated HEX array
 */
uint8_t* char_to_hex(const char* src)
{
    uint8_t* hex_string = (uint8_t*)malloc(strlen(src) / 2);
    if (!hex_string) {
        std::cerr << "ERROR: MEMALLOC operation failed." << std::endl;
        return nullptr;
    }
    // Reset hex_string to all zeros
    for (uint32_t i = 0; i < (strlen(src) / 2); i++) {
        hex_string[i] = 0;
    }

    if (!hex_string)
        return nullptr;
    for (uint32_t i = 0; i < strlen(src); i+=2) {
        for (uint8_t j = 0; j < 2; j++) {
            if ((src[i + j] >= '0') && (src[i + j] <= '9')) {
                hex_string[i / 2] += (src[i + j] - '0') * (j ? 1 : 16);
                continue;
            }
            if ((src[i + j] >= 'A') && (src[i + j] <= 'F')) {
                hex_string[i / 2] += (10 + (src[i + j] - 'A')) * (j ? 1 : 16);
                continue;
            }
            if ((src[i + j] >= 'a') && (src[i + j] <= 'f')) {
                hex_string[i / 2] += (10 + (src[i + j] - 'a')) * (j ? 1 : 16);
                continue;
            }
            std::cerr << "ERROR: Unrecognized symbol \'" << src[i + j] << "\' in place of a hexadecimal value." << std::endl;
            free(hex_string);
            return nullptr;
        }
    }
    return hex_string;
}

int main(const int argc, const char** argv)
{
    // No ARGS => print help message
    if (argc == 1) {
        printf("SHA256, MAC and Lenght Extension Attack demonstration tool.\n");
        printf("Program has four modes:\n");
        printf("\t- SHA256 calculation\n");
        printf("\t- MAC calculation\n");
        printf("\t- MAC validation\n");
        printf("\t- Length extrnsion attack demonstration\n\n");
        printf("For SHA256, add '-c' parameter\n");
        printf("For MAC, add '-s' along with '-k passwd' to specify password\n");
        printf("For MAC verification, add '-v' along with '-k passwd' and '-m MAC' to validate\n");
        printf("For LEA demonstration, add '-e' along with '-m MAC', '-n passwdlen' and '-a extension'\n\n");
        printf("**Please note that the program takes input message from STDIN.\n");
        return 1;
    }

    MAC m;
    mandatory_args tos = initial_sweep(argc, argv);
    int passwd_idx = 0;
    int mac_idx = 0;
    int extended_msg_idx = 0;
    uint8_t* hex_mac = nullptr;
    uint8_t* extended_msg = nullptr;
    uint8_t* last_block = nullptr;
    uint64_t last_len = 0;
    int16_t passwd_len;
    bool result;
    switch (tos) {
        // SHA256 calculation
        case (mandatory_args::mc):
            if (argc > 2) {
                std::cerr << "Warning: Parameter '-c' doesn't need any more parameters." << std::endl;
            }
            m.hash();
            break;

        // MAC calculation
        case (mandatory_args::ms):
            passwd_idx = find_supplementary(argv, argc, "-k");
            if (passwd_idx < 1) {
                std::cerr << "ERROR: Parameter '-k' or it's value missing." << std::endl;
                return 1;
            }
            if (argc > 4)
                std::cerr << "Warning: More parameters than expected." << std::endl;
            m.setPasswd(argv[passwd_idx], strlen(argv[passwd_idx]));
            m.mac();
            break;
        
        // MAC Validation
        case (mandatory_args::mv):
            passwd_idx = find_supplementary(argv, argc, "-k");
            if (passwd_idx < 1) {
                std::cerr << "ERROR: Parameter '-k' or it's value missing." << std::endl;
                return 1;
            }
            mac_idx = find_supplementary(argv, argc, "-m");
            if (mac_idx < 1) {
                std::cerr << "ERROR: Parameter '-m' or it's value missing." << std::endl;
                return 1;
            }
            if (strlen(argv[mac_idx]) != (WORDS_IN_DIGEST * WB * 2)) {
                std::cerr << "ERROR: MAC is supposed to consist of " << (WORDS_IN_DIGEST * WB * 2) << " characters." << std::endl;
                return 1;
            }
            hex_mac = char_to_hex(argv[mac_idx]);
            if (!hex_mac)
                return 1;
            m.setPasswd(argv[passwd_idx], strlen(argv[passwd_idx]));
            result = m.verify((WORD*)hex_mac, 1);
            free(hex_mac);
            return result;

        // LEA Demonstration
        case (mandatory_args::me):
            // Length Extention Attack
            // In this context passwd_idx means passwd_length_idx (reusing variable)
            passwd_idx = find_supplementary(argv, argc, "-n");
            if (passwd_idx < 1) {
                std::cerr << "ERROR: Parameter '-n' or it's value missing." << std::endl;
                return 1;
            }
            passwd_len = atoi(argv[passwd_idx]);
            if (passwd_len < 0) {
                std::cerr << "ERROR: Value of parameter '-n' is NaN." << std::endl;
                return 1;
            }
            mac_idx = find_supplementary(argv, argc, "-m");
            if (mac_idx < 1) {
                std::cerr << "ERROR: Parameter '-m' or it's value missing." << std::endl;
                return 1;
            }
            if (strlen(argv[mac_idx]) != (WORDS_IN_DIGEST * WB * 2)) {
                std::cerr << "ERROR: MAC is supposed to consist of " << (WORDS_IN_DIGEST * WB * 2) << " characters." << std::endl;
                return 1;
            }
            hex_mac = char_to_hex(argv[mac_idx]);
            if (!hex_mac)
                return 1;
            extended_msg_idx = find_supplementary(argv, argc, "-a");
            if (extended_msg_idx < 1) {
                std::cerr << "ERROR: Parameter '-a' or it's value missing." << std::endl;
                return 1;
            }
            extended_msg = (uint8_t*)(argv[extended_msg_idx]);
            m.__set_init_hash(hex_mac, 4);
            // Read message from last block from stdin, allocate space for extension
            last_len = read_stdin(&last_block);
            // Pad the last block to 56 bytes
            pad((void**)&last_block, strlen((char*)last_block), (WORDS_IN_BLOCK - 2) * WB);
            // Add length of message == length of message + passwd length
            last_len += passwd_len;
            // Append bit length after padding
            for (uint8_t i = (WORDS_IN_BLOCK - 2) * WB; i < BLOCK_SIZEB; i++) {
                last_block[i] = ((last_len * 8) >> (BLOCK_SIZEB - i - 1) * 8) & 0xff;
            }
            // Beginning of the attack
            // push extension to stdin so SHA256 tool can read it
            for (int16_t i = strlen((char*)extended_msg) - 1; i >= 0; i--)
                ungetc(extended_msg[i], stdin);
            // Adjust last_len to a value given by equation last_len = k * 64(<- block size)
            last_len = (last_len % BLOCK_SIZEB) > 0 ? ((last_len / BLOCK_SIZEB) + 1) * BLOCK_SIZEB : (last_len / BLOCK_SIZEB) * BLOCK_SIZEB;
            // Based on the public acccessibility of implementation of this tool (https://github.com/JurajMariani/mac_sha256)
            // we can infer the position of content_len and set it to last_len
            *(uint64_t*)(((uint8_t*)&m) + BLOCK_SIZEB + sizeof(uint8_t*) + sizeof(uint8_t*)) = last_len;
            // Execute hash calculation -- should print correct hash demonstrating the attack
            m.hash();
            // Print extended message
            pretty_print(last_block, extended_msg);
            // Free allocated memory
            free(last_block);
            free(hex_mac);
            break;
        
        default:
            std::cerr << "ERROR: Exactly one function identifying parameter required. More/Less/Unknown given." << std::endl;
            return 1;
    }
    return 0;
}