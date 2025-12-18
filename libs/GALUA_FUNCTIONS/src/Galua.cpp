#include "../include/Galua.h"


std::byte GaloisFieldService::add(const std::byte &first, const std::byte &second) {
    return first ^ second;
}

std::byte GaloisFieldService::multiply(const std::byte &first,
                                       const std::byte &second,
                                       const std::byte &mod) {
    uint8_t a = static_cast<uint8_t>(first);
    uint8_t b = static_cast<uint8_t>(second);
    if (!is_irreducible(mod)){
        throw std::invalid_argument("Modul is reducible");
    }
    uint8_t m = static_cast<uint8_t>(mod);
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & (1 << i)) {
            result ^= a;
        }
        bool carry = a & 0x80;
        a <<= 1;
        if (carry) {
            a ^= m;
        }
    }
    return static_cast<std::byte>(result);
}

bool GaloisFieldService::is_irreducible(const std::byte &mod) {
    uint8_t m = std::to_integer<uint8_t>(mod);
    uint16_t poly = 0x100 | m;
    if ((m & 0x01) == 0) return false;
    uint8_t bit_count = 0;
    for (int i = 0; i < 8; i++) {
        if (m & (1 << i)) bit_count++;
    }
    if ((1 + bit_count) % 2 == 0) return false;  // Делится на x+1
    constexpr uint8_t divisors[][2] = {
            {2, 0x07},  // x² + x + 1
            {3, 0x0B},  // x³ + x + 1
            {3, 0x0D},  // x³ + x² + 1
            {4, 0x13},  // x⁴ + x + 1
            {4, 0x19},  // x⁴ + x³ + 1
            {4, 0x1F}   // x⁴ + x³ + x² + x + 1
    };

    for (const auto& [deg, div] : divisors) {
        uint8_t degree = deg;
        uint8_t divisor_low = div & ((1 << degree) - 1);
        uint16_t remainder = poly;
        uint8_t rem_degree = 8;
        while (rem_degree >= degree) {
            uint16_t full_divisor = (1 << degree) | divisor_low;
            int shift = rem_degree - degree;
            remainder ^= (full_divisor << shift);
            rem_degree = 0;
            uint16_t temp = remainder;
            while (temp >>= 1) rem_degree++;
        }

        if (remainder == 0) {
            return false;
        }
    }
    return true;
}

std::byte GaloisFieldService::power(const std::byte &base, const std::byte &exponent, const std::byte &mod) {
    std::byte result = std::byte{1};
    std::byte base_pow = base;
    uint8_t exp = std::to_integer<uint8_t>(exponent);

    while (exp > 0) {
        if (exp & 1) {
            result = multiply(result, base_pow, mod);
        }
        base_pow = multiply(base_pow, base_pow, mod);
        exp >>= 1;
    }

    return result;
}

std::byte GaloisFieldService::inverse(const std::byte &element, const std::byte &mod) {
    if (!is_irreducible(mod)) {
        throw std::invalid_argument("Modulus is reducible");
    }
    return power(element, std::byte{254}, mod);
}

void GaloisFieldService::generate_irreducible_polynoms() {
    irreducible_polynoms.clear();

    std::cout << "Generating irreducible polynomials of degree 8..." << std::endl;
    for (uint16_t i = 0; i < 256; i++) {
        std::byte poly_byte = static_cast<std::byte>(i);
        uint8_t val = static_cast<uint8_t>(poly_byte);
        if ((val & 0x01) == 0) continue;
        uint8_t parity = val;
        parity ^= parity >> 4;
        parity ^= parity >> 2;
        parity ^= parity >> 1;
        if ((parity & 0x01) == 0) {
        } else {
            continue;
        }
        if (is_irreducible(poly_byte)) {
            irreducible_polynoms.push_back(poly_byte);
        }
    }
    if (irreducible_polynoms.size() != 30) {
        throw std::runtime_error("Expected 30 irreducible polynomials, found " +
                                 std::to_string(irreducible_polynoms.size()));
    }
    std::cout << "Generated " << irreducible_polynoms.size()
              << " irreducible polynomials." << std::endl;
}

void GaloisFieldService::print_irreducible_polynom(size_t size){
    std::cout << "Usseble polynom = ";
    uint8_t val = static_cast<uint8_t>(irreducible_polynoms[size]);
    std::bitset<8> bits(val);
    std::cout << "x^8 + ";
    bool first_term = true;
    for (int j = 7; j >= 0; j--) {
        if (bits[j]) {
            if (!first_term) std::cout << " + ";
            if (j == 0) {
                std::cout << "1";
            } else if (j == 1) {
                std::cout << "x";
            } else {
                std::cout << "x^" << j;
            }
            first_term = false;
        }
    }

    if (first_term) {
        std::cout << "0";
    }

    std::cout << std::endl;
}

void GaloisFieldService::print_irreducible_polynom(const std::byte& current){
    std::cout << "Usseble polynom = ";
    uint8_t val = static_cast<uint8_t>(current);
    std::bitset<8> bits(val);
    std::cout << "x^8 + ";
    bool first_term = true;
    for (int j = 7; j >= 0; j--) {
        if (bits[j]) {
            if (!first_term) std::cout << " + ";
            if (j == 0) {
                std::cout << "1";
            } else if (j == 1) {
                std::cout << "x";
            } else {
                std::cout << "x^" << j;
            }
            first_term = false;
        }
    }

    if (first_term) {
        std::cout << "0";
    }

    std::cout << std::endl;
}

void GaloisFieldService::print_irreducible_polynoms() {
    std::cout << "Irreducible polynomials of degree 8:" << std::endl;
    std::cout << "=====================================" << std::endl;
    for (size_t i = 0; i < irreducible_polynoms.size(); i++) {
        uint8_t val = static_cast<uint8_t>(irreducible_polynoms[i]);
        std::cout << "[" << (i + 1) << "] ";
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(val) << std::dec << " = ";

        std::bitset<8> bits(val);
        std::cout << "x^8 + ";
        bool first_term = true;
        for (int j = 7; j >= 0; j--) {
            if (bits[j]) {
                if (!first_term) std::cout << " + ";
                if (j == 0) {
                    std::cout << "1";
                } else if (j == 1) {
                    std::cout << "x";
                } else {
                    std::cout << "x^" << j;
                }
                first_term = false;
            }
        }

        if (first_term) {
            std::cout << "0";
        }

        std::cout << std::endl;
    }
    std::cout << "=====================================" << std::endl;
}

GaloisFieldService::GaloisFieldService() {
    generate_irreducible_polynoms();
}

std::byte GaloisFieldService::cyclic_shift_left(const std::byte &first, size_t amount) {
    uint8_t value = static_cast<uint8_t>(first);
    amount %= 8;
    uint8_t result = (value << amount) | (value >> (8 - amount));
    return static_cast<std::byte>(result);
}

std::byte GaloisFieldService::cyclic_shift_right(const std::byte &first, size_t amount) {
    uint8_t value = static_cast<uint8_t>(first);
    amount %= 8;
    uint8_t result = (value >> amount) | (value << (8 - amount));
    return static_cast<std::byte>(result);
}

STATE GaloisFieldService::ShiftRows(const STATE &state) {
    STATE result(state);
    size_t current = (state[0].size() / 2) - 2;
    for (size_t i = 1; i < 4; i++) {
        result[i] = bit_op::cycleRotateBitsLeft(state[i], PERMUTATIONSFORSHIFTROWS[current][i - 1] * 8, state[i].size() * 8);
    }
    return result;
}

STATE GaloisFieldService::invShiftRows(const STATE &state) {
    STATE result(state);
    size_t current = (state[0].size() / 2) - 2;
    for (size_t i = 1; i < 4; i++) {
        result[i] = bit_op::cycleRotateBitsRight(state[i], PERMUTATIONSFORSHIFTROWS[current][i - 1] * 8, state[i].size() * 8);
    }
    return result;
}

STATE GaloisFieldService::mixColumns(const STATE &state, const std::byte &mod) {
    STATE result(state);
    for (size_t i = 0; i < state[0].size(); i++) {
        for (size_t j = 0; j < 4; j++) {
            result[j][i] = std::byte{0x00};
            for (size_t k = 0; k < 4; k++) {
                if (MIXCOLUMNSMATRIX[j][k] == std::byte{0x01}){
                    result[j][i] = add(result[j][i], state[k][i]);
                    continue;
                }
                result[j][i] = add(result[j][i], multiply(MIXCOLUMNSMATRIX[j][k], state[k][i], mod));
            }
        }
    }
    return result;
}

STATE GaloisFieldService::invmixColumns(const STATE &state, const std::byte &mod) {
    STATE result(state);
    for (size_t i = 0; i < state[0].size(); i++) {
        for (size_t j = 0; j < 4; j++) {
            result[j][i] = std::byte{0x00};
            for (size_t k = 0; k < 4; k++) {
                result[j][i] = add(result[j][i], multiply(INVMIXCOLUMNSMATRIX[j][k], state[k][i], mod));
            }
        }
    }
    return result;
}

STATE GaloisFieldService::addRoundKey(const STATE &state, const INFO &round_key) {
    STATE result(state);
    for (size_t i = 0; i < state[0].size(); i++){
        for (size_t j = 0; j < 4; j++) {
            result[j][i] = GaloisFieldService::add(result[j][i], round_key[i * 4 + j]);
        }
    }
    return result;
}

STATE GaloisFieldService::addRoundKey(const STATE &state, const STATE &round_key) {
    STATE result(state);
    for (size_t i = 0; i < state[0].size(); i++) {
        for (size_t j = 0; j < state.size(); ++j) {
            result[i][j] = add(result[i][j], round_key[i][j]);
        }
    }
    return result;
}

STATE GaloisFieldService::make_state(const INFO &data, size_t amount_of_bytes_in_line) {
    INFO line(amount_of_bytes_in_line, std::byte{0x00});
    STATE result(4, line);
    for (size_t j = 0; j < amount_of_bytes_in_line; j++){
        for (size_t i = 0; i < 4; i++){
            result[i][j] = data[j * 4 + i];
        }
    }
    return result;
}

INFO GaloisFieldService::make_INFO(const STATE& data, size_t amount_of_bytes_in_line) {
    INFO result(4 * amount_of_bytes_in_line, std::byte{0x00});
    for (size_t j = 0; j < amount_of_bytes_in_line; j++){
        for (size_t i = 0; i < 4; i++) {
            result[j * 4 + i] = data[i][j];
        }
    }
    return result;
}

std::byte GaloisFieldService::take_polynom_by_number(size_t size){
    if (size >= 30) {
        throw std::invalid_argument{"There is only 30 polynoms"};
    }
    return irreducible_polynoms[size];
}

void print_state(const STATE &state) {
    size_t num_rows = state.size();
    size_t num_cols = state[0].size();
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (size_t row = 0; row < num_rows; ++row) {
        std::cout << "Row " << row << ": ";
        for (size_t col = 0; col < num_cols; ++col) {
            std::cout << "0x" << std::setw(2)
                      << static_cast<int>(state[row][col]) << " ";
        }
        std::cout << std::endl;
    }

    std::cout << std::dec << std::setfill(' ') << std::nouppercase;
}

void print_state_in_line(const STATE &state) {
    size_t num_rows = state.size();
    size_t num_cols = state[0].size();
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (size_t col = 0; col < num_cols; ++col) {
        for (size_t row = 0; row < num_rows; ++row) {
            std::cout << "0x" << std::setw(2)
                      << static_cast<int>(state[row][col]) << " ";
        }
    }
    std::cout << std::dec << std::setfill(' ') << std::nouppercase << std::endl;
}
