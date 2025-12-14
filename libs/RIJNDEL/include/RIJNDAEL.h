#ifndef CRYPT_RIJNDAEL_H
#define CRYPT_RIJNDAEL_H

#include "../../SymmetricContext/include/SymmetricContext.h"
#include "../../GALUA_FUNCTIONS/include/Galua.h"
#include <cstring>
#include <array>
#include <memory>

const std::byte S_box_constant = std::byte{0x63};
const std::byte inversed_S_box_constant = std::byte{0x05};

class SboxGenerator {
private:
    std::array<std::byte, 256> Sbox;
    std::array<std::byte, 256> invSbox;
    std::byte mod;
    void initialize_Sbox();
    void initialize_invSbox();
public:
    SboxGenerator(const std::byte& polynom);
    std::byte take_Sbox_byte(size_t number) const;
    std::byte take_Sbox_byte(std::byte number) const;
    std::byte take_invSbox_byte(size_t number) const;
    std::byte take_invSbox_byte(std::byte number) const;
    void printSbox() const;
    void printInvSbox() const;
};

class RconGenerator {
private:
    std::array<std::byte, 20> Rcon;
    std::byte mod;
    void initialize_Rcon();
public:
    RconGenerator(const std::byte& polynom);
    std::byte take_Rcon_byte(size_t number) const;
    INFO take_Rcon_row(size_t number) const;
};

class RIJNDAELKeysGenerator {
private:
    static void print_single_round_key(const INFO& round_key,
                                       size_t round_number,
                                       size_t Nb_bytes);
    std::shared_ptr<SboxGenerator> Sbox_generator;
    std::shared_ptr<RconGenerator> Rcon_generator;
public:
    RIJNDAELKeysGenerator(std::shared_ptr<SboxGenerator> Sbox, std::shared_ptr<RconGenerator> Rcon);
    std::vector<INFO> make_round_keys(const INFO& key, size_t amount_of_rounds, size_t Nb);
    static void print_all_round_keys(const std::vector<INFO>& round_keys,
                                     size_t Nb_bytes);
};

class RIJNDAELRound{
private:
    std::shared_ptr<SboxGenerator> Sbox_generator;
    std::shared_ptr<RconGenerator> Rcon_generator;
    std::byte mod;
public:
    RIJNDAELRound(std::shared_ptr<SboxGenerator> Sbox_generator, std::shared_ptr<RconGenerator> Rcon_generator, const std::byte& mod);
    STATE encryption_conversion(const STATE& data, const INFO& round_key);
    STATE decryption_conversion(const STATE& data, const INFO& round_key);
};

class Rijndael : public SymmetricAlgorithm {
private:
    INFO key;
    std::shared_ptr<SboxGenerator> Sbox_generator;
    std::shared_ptr<RconGenerator> Rcon_generator;
    std::shared_ptr<RIJNDAELKeysGenerator> key_generator;
    std::shared_ptr<RIJNDAELRound> encrypt_round;
    std::vector<INFO> round_keys;
    size_t Nb;
    size_t amount_of_rounds;
    std::byte mod;
public:
    Rijndael(size_t b_size, const std::byte& mod, const INFO& key);
    Rijndael(size_t b_size, size_t number_of_polynom, const INFO& key);
    INFO encrypt(const INFO& data) override;
    INFO decrypt(const INFO& data) override;
};

#endif //CRYPT_RIJNDAEL_H
