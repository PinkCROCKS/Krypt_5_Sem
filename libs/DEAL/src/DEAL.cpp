#include "DEAL.h"

std::vector<INFO> DEAlKeysGenerator::make_round_keys(const INFO &key, size_t amount_of_rounds) {
    DES des(key_for_des);
    std::vector<INFO> result;
    if (key.size() == 16){
        INFO K1{8};
        INFO K2{8};
        std::copy(key.begin(), key.begin() + 8, K1.begin());
        std::copy(key.begin() + 8, key.end(), K2.begin());
        result.push_back(des.encrypt(K1));
        result.push_back(des.encrypt(bit_op::xor_vectors(K2, result[0], 8)));
        for (size_t i = 2, pow = 1; i < 6; i++, pow *= 2){
            INFO current_key = (i % 2 == 0) ? K1 : K2;
            INFO number = magic_64bit_number(pow);
            auto xored_info_for_key = bit_op::xor_vectors(bit_op::xor_vectors(current_key, number, 8), result[i - 1], 8);
            result.push_back(des.encrypt(xored_info_for_key));
        }
    } else if (key.size() == 24){
        INFO K1{8};
        INFO K2{8};
        INFO K3{8};
        std::vector<INFO> Ks {K1, K2, K3};
        std::copy(key.begin(), key.begin() + 8, K1.begin());
        std::copy(key.begin() + 8, key.begin() + 16, K2.begin());
        std::copy(key.begin() + 16, key.end(), K3.begin());
        result.push_back(des.encrypt(K1));
        result.push_back(des.encrypt(bit_op::xor_vectors(K2, result[0], 8)));
        result.push_back(des.encrypt(bit_op::xor_vectors(K3, result[1], 8)));
        for (size_t i = 3, pow = 1; i < 6; i++, pow *= 2){
            INFO current_key = Ks[i % 3];
            INFO number = magic_64bit_number(pow);
            auto xored_info_for_key = bit_op::xor_vectors(bit_op::xor_vectors(current_key, number, 8), result[i - 1], 8);
            result.push_back(des.encrypt(xored_info_for_key));
        }
    } else if (key.size() == 32) {
        INFO K1{8};
        INFO K2{8};
        INFO K3{8};
        INFO K4{8};
        std::vector<INFO> Ks {K1, K2, K3, K4};
        std::copy(key.begin(), key.begin() + 8, K1.begin());
        std::copy(key.begin() + 8, key.begin() + 16, K2.begin());
        std::copy(key.begin() + 16, key.end(), K3.begin());
        std::copy(key.begin() + 24, key.end(), K4.begin());
        result.push_back(des.encrypt(K1));
        result.push_back(des.encrypt(bit_op::xor_vectors(K2, result[0], 8)));
        result.push_back(des.encrypt(bit_op::xor_vectors(K3, result[1], 8)));
        result.push_back(des.encrypt(bit_op::xor_vectors(K4, result[2], 8)));
        for (size_t i = 4, pow = 1; i < 8; i++, pow *= 2){
            INFO current_key = Ks[i % 4];
            INFO number = magic_64bit_number(pow);
            auto xored_info_for_key = bit_op::xor_vectors(bit_op::xor_vectors(current_key, number, 8), result[i - 1], 8);
            result.push_back(des.encrypt(xored_info_for_key));
        }
    } else {
        throw std::invalid_argument("INCORRECT KEY SIZE FOR DEAL");
    }
    return result;
}

INFO DEAlKeysGenerator::magic_64bit_number(unsigned int i) {
    int bit_pos = i - 1;

    INFO result(8, std::byte{0});

    int byte_index = 7 - (bit_pos / 8);
    int bit_in_byte = bit_pos % 8;

    result[byte_index] = std::byte{1} << (7 - bit_in_byte);
    return result;
}

DEAlNetwork::DEAlNetwork(std::shared_ptr<DEAlKeysGenerator> generator, size_t rounds, const INFO &key) : keys_generator(generator), key(key) {
    amount_of_rounds = rounds;
    round_keys = keys_generator->make_round_keys(key, amount_of_rounds);
}

INFO DEAlNetwork::encrypt(const INFO &data) {
    INFO result{data.size()};
    INFO L{data.size() / 2};
    INFO R{data.size() / 2};
    std::copy(data.begin(), data.begin() + data.size() / 2, L.begin());
    std::copy(data.begin() + data.size() / 2, data.end(), R.begin());
    for(size_t i = 0; i < amount_of_rounds; ++i) {
        DES des(round_keys[i]);
        INFO x = des.encrypt(R);
        x = bit_op::xor_vectors(x, L, L.size());
        L = R;
        R = x;

    }
    std::copy(L.begin(), L.end(), result.begin());
    std::copy(R.begin(), R.end(), result.begin() + result.size() / 2);
    return result;
}

INFO DEAlNetwork::decrypt(const INFO &data) {
    INFO result{data.size()};
    INFO L{data.size() / 2};
    INFO R{data.size() / 2};
    std::copy(data.begin(), data.begin() + data.size() / 2, L.begin());
    std::copy(data.begin() + data.size() / 2, data.end(), R.begin());
    for(size_t i = 0; i < amount_of_rounds; ++i) {
        DES des(round_keys[round_keys.size() - i - 1]);
        INFO x = des.decrypt(L);
        x = bit_op::xor_vectors(x, R, R.size());
        R = L;
        L = x;

    }
    std::copy(L.begin(), L.end(), result.begin());
    std::copy(R.begin(), R.end(), result.begin() + result.size() / 2);
    return result;
}

INFO DEAlNetwork::get_key() const {
    return key;
}

void DEAlNetwork::set_key(const INFO &new_key) {
    key = new_key;
    round_keys = keys_generator->make_round_keys(new_key, new_key.size());
    amount_of_rounds = (new_key.size() == 24 || new_key.size() == 16) ? 6 : 8;
}


DEAl::DEAl(const INFO &key) : key(key){
    DEAlKeysGenerator generator;
    amount_of_rounds = how_many_rounds();
    network = std::make_shared<DEAlNetwork>(std::make_shared<DEAlKeysGenerator>(generator), amount_of_rounds, key);
    block_size = 16;
}

INFO DEAl::encrypt(const INFO &data) {
    if (data.size() != block_size) {
        throw std::invalid_argument("INCORRECT DATA SIZE FOR ENCRYPTION in DEAL");
    }
    return network->encrypt(data);
}

INFO DEAl::decrypt(const INFO &data) {
    if (data.size() != block_size) {
        throw std::invalid_argument("INCORRECT DATA SIZE FOR DECRYPTION in DEAL");
    }
    return network->decrypt(data);
}

size_t DEAl::how_many_rounds() {
    if (key.size() == 16 || key.size() == 24){
        return 6;
    }
    if (key.size() == 32){
        return 8;
    } else{
        throw std::invalid_argument("INcorrect Key size for DEAL");
    }
}
