#include <iomanip>
#include "Byte.h"

std::byte bit_op::get_bit(size_t number_of_bit, std::byte byte) {
    if (number_of_bit >= 8) {
        throw std::invalid_argument("number of bit can`t be > 7");
    }
    std::byte result = ((std::byte{1} << number_of_bit) & byte) >> number_of_bit;
    return result;
}

std::byte bit_op::set_bit(std::byte data, size_t number_of_bit, std::byte byte) {
    if (number_of_bit >= 8) {
        throw std::invalid_argument("number of bit can`t be > 7");
    }
    std::byte result = (byte << number_of_bit) ^ data;
    return result;
}

std::ostream &bit_op::operator<<(std::ostream &os, std::byte b) {
    return os << std::bitset<8>(std::to_integer<int>(b));
}

INFO bit_op::permutations_by_bytes(const INFO& data, const std::vector<size_t>& Pblock, bit_op::PermutationRule rule) {
    size_t amount_of_bytes = Pblock.size() / 8 + 1;
    if (Pblock.size() % 8 == 0){
        amount_of_bytes--;
    }
    INFO answer(amount_of_bytes, std::byte(0));

    size_t division = rule.firstNumber ? 1 : 0;
    if (rule.reverseIndexing){
        for (size_t i = 0; i < Pblock.size(); i++){
            size_t global_bit_number = data.size() * 8 - (Pblock[i] - division) - 1;
            if (global_bit_number > data.size() * 8) {
                throw std::invalid_argument("Incorrect Pblock");
            }
            size_t number_of_byte = (data.size() - 1) - global_bit_number / 8;
            std::byte current = get_bit(7 - global_bit_number % 8, data[number_of_byte]);
            answer[i / 8] = set_bit(answer[i / 8], 7 - (i % 8), current);
        }
    } else {
        for (size_t i = 0; i < Pblock.size(); i++){
            size_t global_bit_number = Pblock[i] - division;
            if (global_bit_number > data.size() * 8) {
                throw std::invalid_argument("Incorrect Pblock");
            }
            size_t number_of_byte = global_bit_number / 8;
            std::byte current = get_bit(7 - global_bit_number % 8, data[number_of_byte]);
            answer[i / 8] = set_bit(answer[i / 8], 7 - (i % 8), current);
        }
    }

    return answer;
}

INFO bit_op::xor_vectors(const INFO &a, const INFO &b, size_t size) {
    if (a.size() < size || b.size() < size) {
        throw std::invalid_argument("Input vectors are too small for XOR operation");
    }
    INFO result;
    result.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        result.push_back(a[i] ^ b[i]);
    }
    return result;
}

void bit_op::print_permissions(const INFO& permissions) {
    for(int i = 0; i < permissions.size(); ++i) {
        std::cout << permissions[i];
    }
    std::cout << std::endl;
}

void bit_op::print_permissions_by_16(const INFO &permissions) {
    std::cout << std::hex << std::uppercase;

    for (size_t i = 0; i < permissions.size(); ++i) {
        std::cout << std::setw(2) << std::setfill('0')
                  << static_cast<int>(permissions[i]) << " ";
    }
    if (permissions.size() % 16 != 0) {
        std::cout << std::endl;
    }
    std::cout << std::dec << std::nouppercase << std::setfill(' ');
}

INFO bit_op::cycleRotateBitsLeft(const INFO &data, size_t n, size_t size) {
    n = n % size;
    std::vector<size_t> p;
    for(size_t i = 0; i < size; ++i) {
        p.push_back((i + n) % size);
    }

    return permutations_by_bytes(data, p, {0, 0});
}

INFO bit_op::cycleRotateBitsRight(const INFO &data, size_t n, size_t size) {
    n = n % size;
    std::vector<size_t> p;
    for(size_t i = 0; i < size; ++i) {
        p.push_back(((i - n) + size) % size);
    }

    return permutations_by_bytes(data, p, {0, 0});
}

INFO bit_op::connect_arrays(const INFO &first, size_t size_a_bits, const INFO &second, size_t size_b_bits) {
    if(size_a_bits > first.size() * 8 || size_b_bits > second.size() * 8) {
        throw std::runtime_error("incorrect number bits");
    }
    INFO concat{first};
    concat.insert(concat.end(), second.begin(), second.end());
    std::vector<size_t> p;
    for (size_t i = 0; i < size_a_bits; ++i) {
        p.push_back(i);
    }
    for (size_t i = 0; i < size_b_bits; ++i) {
        p.push_back(i + first.size() * 8);
    }
    return permutations_by_bytes(concat, p, {0 , 0});
}

size_t bit_op::counting_number_units(const std::byte &byte) {
    size_t number = 0;
    for(size_t i = 0; i < 8; ++i) {
        if(((byte >> (7 - i)) & std::byte{1}) == std::byte{1}) {
            number += 1;
        }
    }
    return number;
}

std::byte
bit_op::get_bit_fixed(const std::vector<std::byte> &input, size_t index, bit_op::PermutationRule rule) {
    if (index - rule.firstNumber >= input.size() * 8 || (index == 0 && rule.firstNumber)) {
        throw std::runtime_error("incorrect index");
    }
    size_t desired_index;
    if (rule.reverseIndexing == 0) {
        desired_index = index - rule.firstNumber;
    } else {
        desired_index = input.size() * 8 - index - 1 + rule.firstNumber;
    }
    return (input[desired_index / 8] >> (7 - desired_index % 8)) & std::byte{1};
}

std::vector<std::byte> bit_op::add_number_to_bytes(const std::vector<std::byte> &data, uint64_t number) {
    std::vector<std::byte> result = data;

    uint64_t carry = number;
    for (int i = result.size() - 1; i >= 0 && carry > 0; --i) {
        uint64_t current_value = static_cast<uint64_t>(result[i]);
        uint64_t sum = current_value + carry;
        result[i] = static_cast<std::byte>(sum & 0xFF);
        carry = sum >> 8;
    }

    return result;
}
