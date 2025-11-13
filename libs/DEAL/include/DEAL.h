#ifndef INC_1_LAB_DEAL_H
#define INC_1_LAB_DEAL_H

#include "../../DES/include/DES.h"

const INFO key_for_des = {std::byte{0x12},
                                  std::byte{0x34},
                                  std::byte{0x56},
                                  std::byte{0x78},
                                  std::byte{0x90},
                                  std::byte{0xAB},
                                  std::byte{0xCD},
                                  std::byte{0xEF}};

class DEAlKeysGenerator : public RoundKeysGenerator {
private:
    INFO magic_64bit_number(unsigned int i);
public:

    std::vector<INFO> make_round_keys(const INFO& key, size_t amount_of_rounds) override;
};

class DEAlNetwork{
private:
    std::shared_ptr<DEAlKeysGenerator> keys_generator;
    std::vector<INFO> round_keys;
    size_t amount_of_rounds;
    INFO key;
public:
    DEAlNetwork(std::shared_ptr<DEAlKeysGenerator> generator, size_t rounds, const INFO& key);
    INFO encrypt(const INFO& data);
    INFO decrypt(const INFO& data);
    INFO get_key() const;
    void set_key(const INFO& new_key);
};

class DEAl : public SymmetricAlgorithm{
private:
    INFO key;
    std::shared_ptr<DEAlNetwork> network;
    size_t amount_of_rounds;

    size_t how_many_rounds(){
        if (key.size() == 16 || key.size() == 24){
            return 6;
        }
        if (key.size() == 32){
            return 8;
        } else{
            throw std::invalid_argument("INcorrect Key size for DEAL");
        }
    }
public:
    DEAl(const INFO& key);
    INFO encrypt(const INFO& data) override;
    INFO decrypt(const INFO& data) override;
};

#endif //INC_1_LAB_DEAL_H
