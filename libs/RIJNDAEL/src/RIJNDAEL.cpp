#include "../include/RIJNDAEL.h"

void print_numeric_key(const INFO& round_key) {
    for(size_t i = 0; i < round_key.size(); ++i) {
        unsigned int byte_value = static_cast<unsigned int>(round_key[i]);
        printf("%02X", byte_value);
        if(i != round_key.size() - 1) {
            printf(" ");
        }
    }
}

SboxGenerator::SboxGenerator(const std::byte& polynom) : mod(polynom) {
    initialize_Sbox();
    initialize_invSbox();
}

void SboxGenerator::initialize_Sbox() {
    for (int i = 0; i < 256; i++) {
        std::byte current{static_cast<unsigned char>(i)};
        auto b = GaloisFieldService::inverse(current, mod);
        auto sum = GaloisFieldService::add(b, GaloisFieldService::cyclic_shift_left(b, 1));
        bit_op::print_permissions({sum});
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 2));
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 3));
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 4));
        sum = GaloisFieldService::add(sum, S_box_constant);
        Sbox[i] = sum;
    }
}

void SboxGenerator::initialize_invSbox() {
    for (int i = 0; i < 256; i++) {
        std::byte b{static_cast<unsigned char>(i)};
        std::byte sum{0};
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 1));
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 3));
        sum = GaloisFieldService::add(sum, GaloisFieldService::cyclic_shift_left(b, 6));
        sum = GaloisFieldService::add(sum, inversed_S_box_constant);
        invSbox[i] = GaloisFieldService::inverse(sum, mod);
    }
}

std::byte SboxGenerator::take_invSbox_byte(size_t number) const {
    if (number >= 256) {
        throw std::out_of_range("S-box index must be between 0 and 255");
    }
    return invSbox[number];
}

std::byte SboxGenerator::take_invSbox_byte(std::byte number) const {
    auto num = static_cast<uint8_t>(number);
    return invSbox[num];
}

std::byte SboxGenerator::take_Sbox_byte(size_t number) const {
    if (number >= 256) {
        throw std::out_of_range("S-box index must be between 0 and 255");
    }
    return Sbox[number];
}

std::byte SboxGenerator::take_Sbox_byte(std::byte number) const {
    auto num = static_cast<uint8_t>(number);
    return Sbox[num];
}

void SboxGenerator::printSbox() const {
    std::cout << "\n=== S-Box (16x16) ===" << std::endl;
    std::cout << std::hex << std::uppercase << std::setfill('0');
    std::cout << "      ";
    for (int i = 0; i < 16; ++i) {
        std::cout << "  " << std::setw(2) << i;
    }
    std::cout << "\n";
    std::cout << "      ";
    for (int i = 0; i < 16; ++i) {
        std::cout << "----";
    }
    std::cout << "-\n";
    for (int row = 0; row < 16; ++row) {
        std::cout << std::setw(2) << row << "  |";
        for (int col = 0; col < 16; ++col) {
            int index = row * 16 + col;
            std::cout << "  " << std::setw(2)
                      << static_cast<int>(Sbox[index]);
        }
        std::cout << std::endl;
    }

    std::cout << std::dec << std::setfill(' ') << std::nouppercase;
    std::cout << "=====================================" << std::endl;
}

void SboxGenerator::printInvSbox() const {
    std::cout << "\n=== Inverse S-Box (16x16) ===" << std::endl;
    std::cout << std::hex << std::uppercase << std::setfill('0');
    std::cout << "      ";
    for (int i = 0; i < 16; ++i) {
        std::cout << "  " << std::setw(2) << i;
    }
    std::cout << "\n";
    std::cout << "      ";
    for (int i = 0; i < 16; ++i) {
        std::cout << "----";
    }
    std::cout << "-\n";
    for (int row = 0; row < 16; ++row) {
        std::cout << std::setw(2) << row << "  |";
        for (int col = 0; col < 16; ++col) {
            int index = row * 16 + col;
            std::cout << "  " << std::setw(2)
                      << static_cast<int>(invSbox[index]);
        }
        std::cout << std::endl;
    }

    std::cout << std::dec << std::setfill(' ') << std::nouppercase;
    std::cout << "=====================================" << std::endl;
}


RconGenerator::RconGenerator(const std::byte &polynom) : mod(polynom){
    initialize_Rcon();
}

void RconGenerator::initialize_Rcon() {
    Rcon[0] = std::byte{0x01};
    for (size_t i = 1; i < 20; i++){
        Rcon[i] = GaloisFieldService::multiply(Rcon[i - 1], std::byte{2}, mod);
    }
}

std::byte RconGenerator::take_Rcon_byte(size_t number) const {
//    if (number >= 14) {
//        throw std::out_of_range("Rcon index must be between 0 and 13");
//    }
    return Rcon[number];
}

INFO RconGenerator::take_Rcon_row(size_t number) const {
    INFO row{take_Rcon_byte(number), std::byte{0}, std::byte{0}, std::byte{0}};
    return row;
}

void RconGenerator::print_Rcon() {
    std::cout << std::hex << std::uppercase << std::setfill('0');
    for (int row = 0; row < 20; ++row) {
        std::cout << "  " << std::setw(2) << static_cast<int>(Rcon[row]);
    }
        std::cout << std::endl;
}

std::vector<INFO> RIJNDAELKeysGenerator::make_round_keys(const INFO &key,
                                                         size_t amount_of_rounds,
                                                         size_t Nb_bytes) {
    if (key.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }
    if (Nb_bytes != 16 && Nb_bytes != 24 && Nb_bytes != 32) {
        throw std::invalid_argument("Block size must be 16, 24, or 32 bytes");
    }
    size_t Nb = Nb_bytes / 4;
    size_t Nk = key.size() / 4;
    size_t total_words = Nb * (amount_of_rounds + 1);
    INFO tempor(4, std::byte{0x00});
    std::vector<INFO> expanded_key(total_words, tempor);
    for (size_t i = 0; i < Nk; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            expanded_key[i][j] = key[i * 4 + j];
        }
    }
    for (size_t i = Nk; i < total_words; ++i) {
        INFO temp = expanded_key[i - 1];
        if (i % Nk == 0) {
            temp = bit_op::cycleRotateBitsLeft(temp, 8, temp.size() * 8);
            for (size_t j = 0; j < 4; ++j) {
                temp[j] = Sbox_generator->take_Sbox_byte(temp[j]);
            }
            auto y = i / Nk - 1;
            INFO rcon_value = Rcon_generator->take_Rcon_row(y);
            temp = bit_op::xor_vectors(temp, rcon_value, 4);
        }
        else if (Nk > 6 && i % Nk == 4) {
            for (size_t j = 0; j < 4; ++j) {
                temp[j] = Sbox_generator->take_Sbox_byte(temp[j]);
            }
        }
        for (size_t j = 0; j < 4; ++j) {
            expanded_key[i][j] = GaloisFieldService::add(expanded_key[i - Nk][j], temp[j]);
        }
    }
    std::vector<INFO> round_keys(amount_of_rounds + 1);
    for (size_t round = 0; round <= amount_of_rounds; ++round) {
        INFO round_key(Nb * 4);
        for (size_t word = 0; word < Nb; ++word) {
            size_t expanded_index = round * Nb + word;
            for (size_t byte = 0; byte < 4; ++byte) {
                round_key[word * 4 + byte] = expanded_key[expanded_index][byte];
            }
        }
        round_keys[round] = round_key;
    }
    return round_keys;
}

RIJNDAELKeysGenerator::RIJNDAELKeysGenerator(std::shared_ptr<SboxGenerator> Sbox, std::shared_ptr<RconGenerator> Rcon) {
    Sbox_generator = Sbox;
    Rcon_generator = Rcon;
}

void RIJNDAELKeysGenerator::print_single_round_key(const INFO &round_key, size_t round_number, size_t Nb_bytes) {
    if (round_key.empty()) return;
    const size_t Nb = Nb_bytes / 4;  // Количество 32-битных слов в блоке
    const size_t num_rows = 4;       // Всегда 4 строки (так как слово = 4 байта)
    const size_t num_cols = Nb;      // Количество столбцов = Nb
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Round Key #" << round_number
              << " (" << round_key.size() * 8 << "-bit)" << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    std::cout << std::hex << std::uppercase << std::setfill('0');
    std::cout << "        ";
    for (size_t col = 0; col < num_cols; ++col) {
        std::cout << " Word" << std::setw(2) << col << "  ";
    }
    std::cout << std::endl;
    std::cout << "       +";
    for (size_t col = 0; col < num_cols; ++col) {
        std::cout << "-------+";
    }
    std::cout << std::endl;
    for (size_t row = 0; row < num_rows; ++row) {
        std::cout << " Byte" << std::setw(1) << row << " |";
        for (size_t col = 0; col < num_cols; ++col) {
            // Индекс в векторе round_key: col * 4 + row
            size_t index = col * 4 + row;
            if (index < round_key.size()) {
                std::cout << "  0x" << std::setw(2)
                          << static_cast<int>(round_key[index]) << "  |";
            } else {
                std::cout << "   ??  |";
            }
        }
        std::cout << std::endl;
        if (row < num_rows - 1) {
            std::cout << "       +";
            for (size_t col = 0; col < num_cols; ++col) {
                std::cout << "-------+";
            }
            std::cout << std::endl;
        }
    }
    std::cout << "       +";
    for (size_t col = 0; col < num_cols; ++col) {
        std::cout << "-------+";
    }
    std::cout << std::endl;
    std::cout << "Bytes: ";
    for (size_t i = 0; i < round_key.size(); ++i) {
        std::cout << "0x" << std::setw(2)
                  << static_cast<int>(round_key[i]) << " ";
        if ((i + 1) % 16 == 0 && i != round_key.size() - 1) {
            std::cout << "\n       ";
        }
    }
    std::cout << std::endl;
    std::cout << std::dec << std::setfill(' ') << std::nouppercase;
}

void RIJNDAELKeysGenerator::print_all_round_keys(const std::vector<INFO> &round_keys, size_t Nb_bytes) {
    if (round_keys.empty()) {
        std::cout << "No round keys to display!" << std::endl;
        return;
    }

    std::cout << "\n" << std::string(70, '*') << std::endl;
    std::cout << "  ROUND KEYS EXPANSION (" << round_keys.size()
              << " round keys, block size: " << Nb_bytes * 8 << "-bit)" << std::endl;
    std::cout << std::string(70, '*') << std::endl;

    // Выводим каждый раундовый ключ
    for (size_t i = 0; i < round_keys.size(); ++i) {
        print_single_round_key(round_keys[i], i, Nb_bytes);
    }
}


RIJNDAELRound::RIJNDAELRound(std::shared_ptr<SboxGenerator> Sbox,
                             std::shared_ptr<RconGenerator> Rcon, const std::byte& mod) : mod(mod){
    Sbox_generator = Sbox;
    Rcon_generator = Rcon;
}

STATE RIJNDAELRound::encryption_conversion(const STATE &data, const INFO &round_key) {
    STATE result(data);
    for (size_t i = 0; i < data.size(); i++){
        for(size_t j = 0; j < data[0].size(); ++j) {
            result[i][j] = Sbox_generator->take_Sbox_byte(data[i][j]);
        }
    }
    result = GaloisFieldService::ShiftRows(result);
    result = GaloisFieldService::mixColumns(result, mod);
    return GaloisFieldService::addRoundKey(result, round_key);
}

STATE RIJNDAELRound::decryption_conversion(const STATE &data, const INFO &round_key) {
    STATE result(data);
    result = GaloisFieldService::invShiftRows(result);
    for (size_t i = 0; i < data.size(); i++){
        for(size_t j = 0; j < data[0].size(); ++j) {
            result[i][j] = Sbox_generator->take_invSbox_byte(result[i][j]);
        }
    }
    result = GaloisFieldService::addRoundKey(result, round_key);
    result = GaloisFieldService::invmixColumns(result, mod);
    return result;
}

INFO Rijndael::encrypt(const INFO &data) {
    STATE state = GaloisFieldService::make_state(data, Nb / 4);
    state = GaloisFieldService::addRoundKey(state, round_keys[0]);
    size_t j = 1;
    for (; j < amount_of_rounds; j++){
        state = encrypt_round->encryption_conversion(state, round_keys[j]);
    }
    for (size_t i = 0; i < state.size(); i++){
        for(size_t j = 0; j < state[0].size(); ++j) {
            state[i][j] = Sbox_generator->take_Sbox_byte(state[i][j]);
        }
    }
    state = GaloisFieldService::ShiftRows(state);
    state = GaloisFieldService::addRoundKey(state, round_keys[j]);
    return GaloisFieldService::make_INFO(state, Nb / 4);
}

INFO Rijndael::decrypt(const INFO &data) {
    STATE state = GaloisFieldService::make_state(data, Nb / 4);
    state = GaloisFieldService::addRoundKey(state, round_keys[amount_of_rounds]);
    size_t j = amount_of_rounds - 1;
    for (; j >= 1; j-- ) {
        state = encrypt_round->decryption_conversion(state, round_keys[j]);
    }
    state = GaloisFieldService::invShiftRows(state);
    for (size_t i = 0; i < state.size(); i++){
        for(size_t j = 0; j < state[0].size(); ++j) {
            state[i][j] = Sbox_generator->take_invSbox_byte(state[i][j]);
        }
    }
    state = GaloisFieldService::addRoundKey(state, round_keys[0]);
    return GaloisFieldService::make_INFO(state, Nb / 4);
}

Rijndael::Rijndael(size_t b_size, const std::byte &mod, const INFO &key) : key(key), mod(mod){
    block_size = b_size;
    Sbox_generator = std::make_shared<SboxGenerator>(mod);
    Rcon_generator = std::make_shared<RconGenerator>(mod);
    Sbox_generator->printSbox();
    Sbox_generator->printInvSbox();
    GaloisFieldService::print_irreducible_polynom(mod);
    RIJNDAELKeysGenerator generator(Sbox_generator, Rcon_generator);
    RIJNDAELRound round(Sbox_generator, Rcon_generator, mod);
    encrypt_round = std::make_shared<RIJNDAELRound>(round);
    key_generator = std::make_shared<RIJNDAELKeysGenerator>(generator);
    if (key.size() == 32 || block_size == 32) {
        amount_of_rounds = 14;
    } else if (block_size == 24 || key.size() == 24) {
        amount_of_rounds = 12;
    } else if (block_size == 16 && key.size() == 16) {
        amount_of_rounds = 10;
    } else {
        throw std::invalid_argument("incorrect block size or key size");
    }
    Nb = block_size;
    round_keys = key_generator->make_round_keys(key, amount_of_rounds, Nb);
}

Rijndael::Rijndael(size_t b_size, size_t number_of_polynom, const INFO &key) : key(key) {
    mod = GaloisFieldService::take_polynom_by_number(number_of_polynom);
    block_size = b_size;
    Sbox_generator = std::make_shared<SboxGenerator>(mod);
    Rcon_generator = std::make_shared<RconGenerator>(mod);
    Sbox_generator->printSbox();
    Sbox_generator->printInvSbox();
    GaloisFieldService::print_irreducible_polynom(number_of_polynom);
    RIJNDAELKeysGenerator generator(Sbox_generator, Rcon_generator);
    RIJNDAELRound round(Sbox_generator, Rcon_generator, mod);
    encrypt_round = std::make_shared<RIJNDAELRound>(round);
    key_generator = std::make_shared<RIJNDAELKeysGenerator>(generator);
    if (key.size() == 32 || block_size == 32) {
        amount_of_rounds = 14;
    } else if (block_size == 24 || key.size() == 24) {
        amount_of_rounds = 12;
    } else if (block_size == 16 && key.size() == 16) {
        amount_of_rounds = 10;
    } else {
        throw std::invalid_argument("incorrect block size or key size");
    }
    Nb = block_size;
    round_keys = key_generator->make_round_keys(key, amount_of_rounds, Nb);
}
