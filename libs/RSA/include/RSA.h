#ifndef CRYPT_RSA_H
#define CRYPT_RSA_H

#include <cstddef>
#include <memory>
#include <filesystem>
#include <optional>
#include "../../PRIMARY_TEST/include/primary_tests.h"
#include "../../BIT_FUNCTIONS/include/Byte.h"
#include "future"

class RSAKeyGenerator{
private:
    const BOOSTED_INT e = 65537;
    std::shared_ptr<PrimeTest> test;
    double min_probability;
    size_t length;
    boost::random::mt19937 gen;
    std::unordered_set<BOOSTED_INT> checked_numbers;
    BOOSTED_INT generate_random();
    bool check_ferma(const BOOSTED_INT& p,const BOOSTED_INT& q);
    bool check_vinner(const BOOSTED_INT& d, const BOOSTED_INT& p,const BOOSTED_INT& q);
public:
    RSAKeyGenerator(Ptests prime_test, double needed_probability, size_t bit_length);
    std::pair<std::pair<BOOSTED_INT, BOOSTED_INT>, std::pair<BOOSTED_INT, BOOSTED_INT>> generate_keys();
};

class RSA {
private:
    size_t length;
    mutable std::mutex mutex;
    std::shared_ptr<RSAKeyGenerator> generator;
    std::pair<BOOSTED_INT, BOOSTED_INT > public_key;
    std::pair<BOOSTED_INT, BOOSTED_INT > private_key;

    BOOSTED_INT convert_to_int(const INFO &block);
    INFO convert_to_bytes_vector(const BOOSTED_INT &block);
    INFO encrypt_single_block(const INFO &data, size_t block_size);
    INFO decrypt_single_block(const INFO &encrypted_block);
public:
    RSA(Ptests test_type, double needed_probability, size_t length);
    INFO encrypt(const INFO& data);
    INFO decrypt(const INFO& data);
    std::future<void> encrypt(const std::filesystem::path &input_file);
    std::future<void> decrypt(const std::filesystem::path &input_file);
    INFO make_padding(const INFO& data, size_t size);
    INFO remove_padding(const INFO& data);
};

#endif //CRYPT_RSA_H
