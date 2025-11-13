#include <iostream>
#include <bitset>
#include <cstddef>
#include "Byte.h"
#include "DEAL.h"

void printHexComparison(const INFO& actual) {
    std::cout << "Actual:   ";
    for (auto b : actual) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(b) << " ";
    }
}

std::vector<INFO> expected_round_keys = {
        {std::byte{0x1B}, std::byte{0x02}, std::byte{0xEF}, std::byte{0xFC}, std::byte{0x70}, std::byte{0x72}}, // Round 1
        {std::byte{0x79}, std::byte{0xAE}, std::byte{0xD9}, std::byte{0xDA}, std::byte{0xC3}, std::byte{0x9E}}, // Round 2
        {std::byte{0x55}, std::byte{0xFC}, std::byte{0x8A}, std::byte{0x42}, std::byte{0xCF}, std::byte{0x99}}, // Round 3
        {std::byte{0x72}, std::byte{0xAD}, std::byte{0xD6}, std::byte{0xDB}, std::byte{0xC4}, std::byte{0x79}}, // Round 4
        {std::byte{0x7D}, std::byte{0xE6}, std::byte{0xB6}, std::byte{0xFE}, std::byte{0xCC}, std::byte{0x4D}}, // Round 5
        {std::byte{0x62}, std::byte{0xC1}, std::byte{0x5F}, std::byte{0xBF}, std::byte{0x9F}, std::byte{0x9F}}, // Round 6
        {std::byte{0xE0}, std::byte{0xAC}, std::byte{0xCA}, std::byte{0x24}, std::byte{0xC1}, std::byte{0x77}}, // Round 7
        {std::byte{0x81}, std::byte{0x44}, std::byte{0xF8}, std::byte{0x5C}, std::byte{0xC3}, std::byte{0xAF}}, // Round 8
        {std::byte{0x0C}, std::byte{0x26}, std::byte{0x1B}, std::byte{0xE5}, std::byte{0x68}, std::byte{0x5F}}, // Round 9
        {std::byte{0x16}, std::byte{0xC8}, std::byte{0xA8}, std::byte{0x31}, std::byte{0x32}, std::byte{0x25}}, // Round 10
        {std::byte{0x96}, std::byte{0x1A}, std::byte{0x2D}, std::byte{0xED}, std::byte{0x14}, std::byte{0xAA}}, // Round 11
        {std::byte{0x88}, std::byte{0x22}, std::byte{0x62}, std::byte{0x31}, std::byte{0xB0}, std::byte{0xDA}}, // Round 12
        {std::byte{0x02}, std::byte{0xDC}, std::byte{0x53}, std::byte{0x8A}, std::byte{0x64}, std::byte{0x46}}, // Round 13
        {std::byte{0x34}, std::byte{0x74}, std::byte{0x9C}, std::byte{0x48}, std::byte{0xFF}, std::byte{0x98}}, // Round 14
        {std::byte{0x3B}, std::byte{0x47}, std::byte{0xF9}, std::byte{0xCB}, std::byte{0xDC}, std::byte{0xD2}}, // Round 15
        {std::byte{0x19}, std::byte{0x9D}, std::byte{0xD8}, std::byte{0x7E}, std::byte{0x63}, std::byte{0x64}}  // Round 16
};

const INFO tested_64 = {std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1},
                        std::byte{0x13}, std::byte{0x34}, std::byte{0x57}, std::byte{0x79},
                        std::byte{0x9B}, std::byte{0xBC}, std::byte{0xDF}, std::byte{0xF1}};

int main(){
    std::byte iiioooio = std::byte(226);
    std::byte iooioiio = std::byte(150);
    std::byte i15 = std::byte(238);
    std::byte i16 = std::byte(68);
    std::byte i17 = std::byte(36);
    std::byte i18 = std::byte(0);
    std::byte i19 = std::byte(255);
    std::byte i20 = std::byte(221);
    std::byte i21 = std::byte(51);
    std::byte i22 = std::byte(153);
    std::vector<std::byte> data({i15, i16, i17, i18, i15, i16, i17, i18});
    std::vector<std::byte> data_for_round({i15, i16, i17, i18});
    std::vector<std::byte> data1{i15, i16, i17, i18, i19, i20, i21, i22};
    std::vector<size_t> Pblock{1, 2, 1, 2};

    KeyOnlyAlgorithm algoritm{{std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                               std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}}};

//    auto d = std::make_shared<KeyOnlyAlgorithm>(algoritm);
    INFO key = {std::byte(119), std::byte(99), std::byte(111), std::byte(30),
                std::byte(241), std::byte(164), std::byte(43), std::byte(34),
                std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};
    INFO key_by_matvei = { std::byte{0xAB},
                           std::byte{0x75},
                           std::byte{0x08},
                           std::byte{0x55},
                           std::byte{0xC2},
                           std::byte{0x07},
                           std::byte{0x25}};
    INFO init_vector{std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                     std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};
    FeystelKeysGeneretion generator;;
    auto d = std::make_shared<DES>(key_by_matvei);
//    d.get()->set_block_size(8);

    SymmetricEncryptingContext context(Random_Delta, PKCS7, init_vector, d);std::filesystem::path inputPath = "image.jpg";
    std::filesystem::path encryptedOutput = inputPath.stem().string() + "_encrypted.bin";
    std::filesystem::path decryptedOutput = inputPath.stem().string() + "_decrypted" + inputPath.extension().string();

    std::cout << "Input file: " << inputPath << std::endl;
    std::cout << "Encrypted file: " << encryptedOutput << std::endl;
    std::cout << "Decrypted file: " << decryptedOutput << std::endl;

// Шифрование с замером времени
    auto encryptStart = std::chrono::high_resolution_clock::now();
    auto encryptFuture = context.encrypt(inputPath, encryptedOutput);
    encryptFuture.get();
    auto encryptEnd = std::chrono::high_resolution_clock::now();
    auto encryptDuration = std::chrono::duration_cast<std::chrono::milliseconds>(encryptEnd - encryptStart);
    std::cout << "File encrypted successfully" << std::endl;
    std::cout << "Encryption time: " << encryptDuration.count() << " ms" << std::endl;

// Дешифрование с замером времени
    auto decryptStart = std::chrono::high_resolution_clock::now();
    auto decryptFuture = context.decrypt(encryptedOutput, decryptedOutput);
    decryptFuture.get();
    auto decryptEnd = std::chrono::high_resolution_clock::now();
    auto decryptDuration = std::chrono::duration_cast<std::chrono::milliseconds>(decryptEnd - decryptStart);
    std::cout << "File decrypted successfully" << std::endl;
    std::cout << "Decryption time: " << decryptDuration.count() << " ms" << std::endl;

// Вывод общего времени
    auto totalTime = encryptDuration + decryptDuration;
    std::cout << "Total processing time: " << totalTime.count() << " ms" << std::endl;

//    auto y = context.encrypt(data).get();
//    bit_op::print_permissions(y);
//    auto i = context.decrypt(y);
//    bit_op::print_permissions(i.get());
//    bit_op::print_permissions(data);

//
//    FeystelKeysGeneretion generator;
//    FeystelFunction function;
    return 0;
}