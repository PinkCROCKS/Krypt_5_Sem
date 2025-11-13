#include "Feystel.h"
FeystelNet::FeystelNet(std::shared_ptr <FeystelKeysGeneretion> generator,
                       std::shared_ptr <FeystelFunction> feystel_function, size_t rounds, const INFO& key) : keys_generator(generator), function(feystel_function), amount_of_rounds(rounds), key(key){
    round_keys = keys_generator->make_round_keys(key, amount_of_rounds);
    if (key.size() != 7 && key.size() != 8){
        throw std::invalid_argument("Incorrect_key size, must be 7 bytes? but given " + key.size());
    }
}

INFO FeystelNet::encrypt(const INFO &data) {
    INFO result{data.size()};
    INFO L{data.size() / 2};
    INFO R{data.size() / 2};
    std::copy(data.begin(), data.begin() + data.size() / 2, L.begin());
    std::copy(data.begin() + data.size() / 2, data.end(), R.begin());
    for(size_t i = 0; i < amount_of_rounds; ++i) {
        INFO x = function->encryption_conversion(R, round_keys[i]);
        x = bit_op::xor_vectors(x, L, L.size());
        L = R;
        R = x;

    }
    std::copy(L.begin(), L.end(), result.begin());
    std::copy(R.begin(), R.end(), result.begin() + result.size() / 2);
    return result;
}

INFO FeystelNet::decrypt(const INFO &data) {
    INFO result{data.size()};
    INFO L{data.size() / 2};
    INFO R{data.size() / 2};
    std::copy(data.begin(), data.begin() + data.size() / 2, L.begin());
    std::copy(data.begin() + data.size() / 2, data.end(), R.begin());
    for(size_t i = 0; i < amount_of_rounds; ++i) {
        INFO x = function->encryption_conversion(L, round_keys[round_keys.size() - i - 1]);
        x = bit_op::xor_vectors(x, R, R.size());
        R = L;
        L = x;

    }
    std::copy(L.begin(), L.end(), result.begin());
    std::copy(R.begin(), R.end(), result.begin() + result.size() / 2);
    return result;
}

INFO FeystelNet::get_key() const {
    return key;
}

void FeystelNet::set_key(const INFO &new_key) {
    key = new_key;
    round_keys = keys_generator->make_round_keys(key, amount_of_rounds);
}

INFO e_expansion_function(const INFO &data) {
    return bit_op::permutations_by_bytes(data, EPermutation, {0, 1});
}

std::vector<std::bitset<6>> FeystelFunction::make_Blocks_of_6_bits(const INFO &data) {
    std::vector<std::bitset<6>> B(8);
    for (size_t i = 0; i < B.size(); i++){
        for (size_t j = 0; j < 6; j++) {
            std::byte current_byte = data[(i * 6 + j) / 8];
            auto current_bit_value = (bit_op::get_bit(7 - (i * 6 + j) % 8, current_byte) == std::byte(1));
            B[i].set(5 - j, current_bit_value);
        }
    }
    return B;
}

std::vector<size_t> FeystelFunction::make_a_b_components(const std::bitset<6> &Bi) {
    size_t a = Bi.test(5) * 2 + Bi.test(0) * 1;
    size_t b = Bi.test(4) * 8 + Bi.test(3) * 4 + Bi.test(2) * 2 + Bi.test(1) * 1;
    return std::vector<size_t> {a, b};
}

INFO FeystelFunction::s_permutation(const std::vector<std::bitset<6>> &data) {
    INFO permutated_data(4);
    for (size_t i = 0; i < permutated_data.size(); i++){
        auto first_indexes = make_a_b_components(data[i * 2]);
        auto second_indexes = make_a_b_components(data[i * 2 + 1]);
        size_t first_part_of_vector = S_BLOCKS[i * 2][first_indexes[0]][first_indexes[1]];
        size_t second_part_of_vector = S_BLOCKS[i * 2 + 1][second_indexes[0]][second_indexes[1]];
        permutated_data[i] = std::byte(first_part_of_vector * 16 + second_part_of_vector);
    }
    return permutated_data;
}

INFO FeystelFunction::encryption_conversion(const INFO &data, const INFO &round_key) {
    if (data.size() != 4){
        throw std::invalid_argument("incorrect data size for encryption round, must be 32 get " + data.size());
    }
    if (data.size() != 4){
        throw std::invalid_argument("incorrect round_key size for encryption round, must be 48 get " + round_key.size());
    }
    INFO expanded_data = bit_op::xor_vectors(e_expansion_function(data), round_key, round_key.size());
    auto B = make_Blocks_of_6_bits(expanded_data);
    INFO permutated_data = s_permutation(B);
    auto o = bit_op::permutations_by_bytes(permutated_data, PPermutation, {0, 1});
    return o;
}

INFO FeystelKeysGeneretion::extension_of_key(const INFO &key) {
    std::vector<std::bitset<7>> bits(8);
    for (size_t i = 0; i < bits.size();i++){
        for (size_t j = 0; j < 7;j++){
            std::byte current_byte = key[(i * 7 + j) / 8];
            auto current_bit_value = (bit_op::get_bit(7 - (i * 7 + j) % 8, current_byte) == std::byte(1));
            bits[i].set(6 - j, current_bit_value);
        }
    }
    INFO extended_key(8);
    for (size_t i = 0; i < extended_key.size();i++){
        extended_key[i] = std::byte(bits[i].to_ulong() * 2 + (bits[i].count() % 2 == 0));
    }
    return extended_key;
}

INFO FeystelKeysGeneretion::generate_round_key(const INFO &C, const INFO &D) {
    INFO t = bit_op::connect_arrays(C, 28, D, 28);
    return bit_op::permutations_by_bytes(t, KeyEndPermutation, {0, 1});
}


std::vector<INFO> FeystelKeysGeneretion::make_round_keys(const INFO &key, size_t amount_of_rounds) {
    INFO augmented_key;
    if (key.size() == 7){
        augmented_key = extension_of_key(key);
    } else{
        augmented_key = key;
    }
    INFO C;
    INFO D;
    C = bit_op::permutations_by_bytes(augmented_key, KeyCPermutations, {0, 1});
    D = bit_op::permutations_by_bytes(augmented_key, KeyDPermutations, {0, 1});
    std::vector<INFO> keys;
    for(size_t i = 0; i < amount_of_rounds; ++i) {
        C = bit_op::cycleRotateBitsLeft(C, amount_of_shifts[i], 28);
        D = bit_op::cycleRotateBitsLeft(D, amount_of_shifts[i], 28);
        keys.push_back(generate_round_key(C, D));
    }
    return keys;
}