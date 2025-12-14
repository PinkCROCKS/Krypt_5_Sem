#ifndef CRYPT_GALUA_H
#define CRYPT_GALUA_H

#include <iomanip>
#include "../../BIT_FUNCTIONS/include/Byte.h"

using STATE = std::vector<INFO>;

const std::vector<std::vector<size_t>> PERMUTATIONSFORSHIFTROWS{{1, 2, 3}, {1, 2, 4}, {1, 3, 4}};
const STATE MIXCOLUMNSMATRIX {{std::byte{0x02}, std::byte{0x03}, std::byte{0x01}, std::byte{0x01}},
                              {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x01}},
                              {std::byte{0x01}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}},
                              {std::byte{0x03}, std::byte{0x01}, std::byte{0x01}, std::byte{0x02}}};
const STATE INVMIXCOLUMNSMATRIX {{std::byte{0x0e}, std::byte{0x0b}, std::byte{0x0d}, std::byte{0x09}},
                              {std::byte{0x09}, std::byte{0x0e}, std::byte{0x0b}, std::byte{0x0d}},
                              {std::byte{0x0d}, std::byte{0x09}, std::byte{0x0e}, std::byte{0x0b}},
                              {std::byte{0x0b}, std::byte{0x0d}, std::byte{0x09}, std::byte{0x0e}}};

class GaloisFieldService {
private:
    inline static INFO irreducible_polynoms;
    void generate_irreducible_polynoms();
    static std::byte power(const std::byte &base, const std::byte &exponent, const std::byte &mod);

public:
    GaloisFieldService();
    static void print_irreducible_polynoms();
    static std::byte take_polynom_by_number(size_t size);
    static std::byte add(const std::byte& first, const std::byte& second);
    static std::byte multiply(const std::byte& first, const std::byte& second, const std::byte& mod);
    static std::byte inverse(const std::byte& first, const std::byte& mod);
    static std::byte cyclic_shift_left(const std::byte& first, size_t amount);
    static std::byte cyclic_shift_right(const std::byte& first, size_t amount);
    static bool is_irreducible(const std::byte& mod);
    static STATE ShiftRows(const STATE& state);
    static STATE invShiftRows(const STATE& state);
    static STATE mixColumns(const STATE& state, const std::byte &mod);
    static STATE invmixColumns(const STATE& state, const std::byte &mod);
    static STATE addRoundKey(const STATE& state, const INFO& round_key);
    static STATE addRoundKey(const STATE& state, const STATE& round_key);
    static STATE make_state(const INFO& data, size_t amount_of_bytes_in_line);
    static INFO make_INFO(const STATE& data, size_t amount_of_bytes_in_line);
};

void print_state(const STATE& state);
void print_state_in_line(const STATE &state);

#endif //CRYPT_GALUA_H
