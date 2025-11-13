#include "DES.h"

INFO DES::encrypt(const INFO &data) {
    if (data.size() != 8) {
        throw std::invalid_argument("Incorrect data size for DES Encryption");
    }
    INFO permutated_data = bit_op::permutations_by_bytes(data, IPPermutation, {0, 1});
    INFO encrypted_by_feystel = function->encrypt(permutated_data);
    return bit_op::permutations_by_bytes(encrypted_by_feystel, IPReversePermutation, {0, 1});
}

INFO DES::decrypt(const INFO &data) {
    if (data.size() != 8) {
        throw std::invalid_argument("Incorrect data size for DES Encryption");
    }
    INFO permutated_data = bit_op::permutations_by_bytes(data, IPPermutation, {0, 1});
    INFO decrypted_by_feystel = function->decrypt(permutated_data);
    return bit_op::permutations_by_bytes(decrypted_by_feystel, IPReversePermutation, {0, 1});
}
