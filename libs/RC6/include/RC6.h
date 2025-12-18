#ifndef CRYPT_RC6_H
#define CRYPT_RC6_H

#include "Feystel.h"
#include "Byte.h"
#include "boost/multiprecision/cpp_dec_float.hpp"
#include "../../NUM_FUNCTIONS/include/num_functions.h"

class RC6KeysGenerator {
private:
    size_t w, b;
    INFO make_L(const INFO& key);
    boost::multiprecision::cpp_dec_float_50 golden_ratio() const;
    BOOSTED_INT round_to_boosted_int(boost::multiprecision::cpp_dec_float_50 number);
    BOOSTED_INT P_generator(size_t w);
    BOOSTED_INT Q_generator(size_t w);
public:
    RC6KeysGenerator(size_t w, size_t b);
    std::vector<INFO> make_round_keys(const INFO& key, size_t amount_of_rounds);
    static std::vector<std::byte> convert_to_bytes_vector(const BOOSTED_INT& block);
    static BOOSTED_INT convert_to_cpp_int(const std::vector<std::byte> & block);
    static BOOSTED_INT cycling_rotate_left(const BOOSTED_INT& number, size_t shift, size_t width);
    static BOOSTED_INT cycling_rotate_right(const BOOSTED_INT& number, size_t shift, size_t width);
};

class RC6 : public SymmetricAlgorithm{
private:
    RC6KeysGenerator keys_generator;
    size_t amount_of_rounds;
    INFO key;
    std::vector<INFO> S;
    std::vector<BOOSTED_INT> S_b;
    size_t log2_w(size_t w);
    size_t w;
public:
    RC6(const std::vector<std::byte> & key, size_t block_size=8, size_t number_rounds=20);
    size_t get_block_size();
    std::vector<std::byte> encrypt(const INFO& data) override;
    std::vector<std::byte> decrypt(const INFO& data) override;
    void set_key(const std::vector<std::byte> & key);
    inline static size_t standart_block_size = 8;
    inline static size_t standart_key_size = 32;
};

#endif //CRYPT_RC6_H
