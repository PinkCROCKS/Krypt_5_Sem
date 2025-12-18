#ifndef CRYPT_RC4_H
#define CRYPT_RC4_H

#include <filesystem>
#include <fstream>
#include "../../BIT_FUNCTIONS/include/Byte.h"

class RC4 {
private:
    INFO key;
    INFO S_block;
    size_t i = 0;
    size_t j = 0;

    void KSA();
    std::byte PRGA();
public:
    RC4(const INFO& key);
    void encrypt(const std::filesystem::path &input_file, const std::filesystem::path &output_file);
    void decrypt(const std::filesystem::path& input_file, const std::filesystem::path& output_file);
    void set_key(const INFO& new_key);
};

#endif //CRYPT_RC4_H
