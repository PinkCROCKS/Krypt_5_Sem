#ifndef INC_1_LAB_BYTE_H
#define INC_1_LAB_BYTE_H

#include <vector>
#include <iostream>
#include <bitset>
#include <cstddef>
#include <cstdint>

using INFO = std::vector<std::byte>;
namespace bit_op{
    struct PermutationRule{
        bool reverseIndexing;
        bool firstNumber;
    };

    std::byte get_bit(size_t number_of_bit, std::byte byte);

    std::byte set_bit(std::byte data, size_t number_of_bit, std::byte byte);

    std::ostream& operator<<(std::ostream& os, std::byte b);

    INFO permutations_by_bytes(const INFO& data,const  std::vector<size_t>& Pblock, PermutationRule rule);

    INFO xor_vectors(const INFO &a, const INFO &b, size_t size);

    void print_permissions(const INFO& permissions);
    void print_permissions_by_16(const INFO& permissions);

    INFO cycleRotateBitsLeft(const INFO& data, size_t n, size_t size);
    INFO cycleRotateBitsRight(const INFO& data, size_t n, size_t size);

    INFO connect_arrays(const INFO& first, size_t size_a_bits, const INFO& second, size_t size_b_bits);

    size_t counting_number_units(const std::byte & byte);

    std::byte get_bit_fixed(const std::vector<std::byte> & input, size_t index, bit_op::PermutationRule rule);

    std::vector<std::byte> add_number_to_bytes(const std::vector<std::byte> &data, uint64_t number);
}
#endif //INC_1_LAB_BYTE_H
