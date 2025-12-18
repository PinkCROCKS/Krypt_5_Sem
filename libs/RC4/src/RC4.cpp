//
// Created by Ярослав on 18.12.2025.
//
#include "../include/RC4.h"

void RC4::encrypt(const std::filesystem::path &input_file, const std::filesystem::path &output_file) {
    KSA();
    if (!std::filesystem::exists(input_file)) {
        throw std::runtime_error("NO such file or directory: " + input_file.string());
    }

    std::filesystem::path actual_output_path = output_file;

    std::ifstream in_file(input_file, std::ios::binary);
    std::ofstream out_file(actual_output_path, std::ios::binary);

    if (!in_file.is_open()) {
        throw std::runtime_error("Cannot open input file: " + input_file.string());
    }
    if (!out_file.is_open()) {
        throw std::runtime_error("Cannot open output file: " + actual_output_path.string());
    }
    char c;
    while (in_file.get(c)) {
        std::byte key_byte = this->PRGA();
        std::byte processed_byte = static_cast<std::byte>(c) ^ key_byte;
        out_file.put(static_cast<char>(processed_byte));
    }

    in_file.close();
    out_file.close();
}

void RC4::decrypt(const std::filesystem::path &input_file, const std::filesystem::path &output_file) {
    encrypt(input_file, output_file);
}

void RC4::KSA() {
    S_block.resize(256);
    for (size_t k = 0; k < 256; ++k) {
        S_block[k] = static_cast<std::byte>(k);
    }
    size_t l = 0;
    for (size_t k = 0; k < 256; ++k) {
        l = (l + static_cast<size_t>(S_block[k]) + static_cast<size_t>(key[k % key.size()])) % 256;
        std::swap(S_block[k], S_block[l]);
    }
    i = 0;
    j = 0;
}

std::byte RC4::PRGA() {
    i = (i + 1) % 256;
    j = (j + static_cast<size_t>(S_block[i])) % 256;
    std::swap(S_block[i], S_block[j]);
    return S_block[(static_cast<size_t>(S_block[i]) + static_cast<size_t>(S_block[j])) % 256];
}

RC4::RC4(const INFO &key) : key(key){
    KSA();
}

void RC4::set_key(const INFO &new_key) {
    key = new_key;
    KSA();
}

