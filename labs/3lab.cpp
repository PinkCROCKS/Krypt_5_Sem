//
// Created by Ярослав on 29.11.2025.
//

#include "RIJNDAEL.h"
#include "../libs/GALUA_FUNCTIONS/include/Galua.h"

int main(){
    INFO data{std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
              std::byte{0x44}, std::byte{0x55}, std::byte{0x66}, std::byte{0x77},
              std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
              std::byte{0xcc},std::byte{0xdd}, std::byte{0xee}, std::byte{0xff}};
    INFO key = {
            std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
            std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f},
    };
    INFO key2 = {
            std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
            std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f},
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
            std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
    };
    INFO key3 = {
            std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
            std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f},
            std::byte{0x10}, std::byte{0x11}, std::byte{0x12}, std::byte{0x13},
            std::byte{0x14}, std::byte{0x15}, std::byte{0x16}, std::byte{0x17},
            std::byte{0x18}, std::byte{0x19}, std::byte{0x1a}, std::byte{0x1b},
            std::byte{0x1c}, std::byte{0x1d}, std::byte{0x1e}, std::byte{0x1f},
    };
//    RIJNDAELKeysGenerator generator;
//    auto o = generator.make_round_keys(key, 12);
//    print_numeric_key(o[0]);
//    INFO test1{std::byte{0x04}, std::byte{0xe0}, std::byte{8}, std::byte{12}, std::byte{0}, std::byte{4}, std::byte{8}, std::byte{12}};
//    INFO test2{std::byte{1}, std::byte{5}, std::byte{9}, std::byte{13}, std::byte{1}, std::byte{5}, std::byte{9}, std::byte{13}};
//    INFO test3{std::byte{2}, std::byte{6}, std::byte{10}, std::byte{14}, std::byte{2}, std::byte{6}, std::byte{10}, std::byte{14}};
//    INFO test4{std::byte{3}, std::byte{7}, std::byte{11}, std::byte{15}, std::byte{3}, std::byte{7}, std::byte{11}, std::byte{15}};
//    STATE state{test1, test2, test3, test4};

    GaloisFieldService galua;
    galua.print_irreducible_polynoms();
    std::byte AESmod{0x1b};
//    INFO row0{std::byte{0xd4}, std::byte{0xe0}, std::byte{0xb8}, std::byte{0x1e}};
//    INFO row1{std::byte{0xbf}, std::byte{0xb4}, std::byte{0x41}, std::byte{0x27}};
//    INFO row2{std::byte{0x5d}, std::byte{0x52}, std::byte{0x11}, std::byte{0x98}};
//    INFO row3{std::byte{0x30}, std::byte{0xae}, std::byte{0xf1}, std::byte{0xe5}};
//    STATE state{row0, row1, row2, row3};
//    INFO key_row0{std::byte{0xa0}, std::byte{0x88}, std::byte{0x23}, std::byte{0x2a}};
//    INFO key_row1{std::byte{0xfa}, std::byte{0x54}, std::byte{0xa3}, std::byte{0x6c}};
//    INFO key_row2{std::byte{0xfe}, std::byte{0x2c}, std::byte{0x39}, std::byte{0x76}};
//    INFO key_row3{std::byte{0x17}, std::byte{0xb1}, std::byte{0x39}, std::byte{0x05}};
//    STATE key{key_row0, key_row1, key_row2, key_row3};
//    auto r = GaloisFieldService::mixColumns(state, AESmod);
//    print_state(r);
//    print_state(GaloisFieldService::addRoundKey(r, key));
    SboxGenerator s(AESmod);
    s.printSbox();
//    RconGenerator r(AESmod);
//    RIJNDAELKeysGenerator generator(std::make_shared<SboxGenerator>(s), std::make_shared<RconGenerator>(r));
//    generator.print_all_round_keys(generator.make_round_keys(key, 10, 16), 128);
//    Rijndael r{16, 17, key2};
//
//    INFO testIV = {std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
//              std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};
//    std::optional<INFO> t(testIV);
//    std::shared_ptr<SymmetricAlgorithm> y = std::make_shared<Rijndael>(r);
//    SymmetricEncryptingContext context(Random_Delta, ISO_10126, t, y);
//    std::filesystem::path inputPath = "test.txt";
//    std::filesystem::path encryptedOutput = inputPath.stem().string() + "_encrypted.bin";
//    std::filesystem::path decryptedOutput = inputPath.stem().string() + "_decrypted" + inputPath.extension().string();
//    uintmax_t originalSize = std::filesystem::file_size(inputPath);
//    std::cout << "Размер файла: " << originalSize << " байт ("
//              << originalSize / 1024 / 1024 << " MB)\n";
//
//// Шифрование
//    auto start1 = std::chrono::high_resolution_clock::now();
//    auto temp = context.encrypt(inputPath, encryptedOutput);
//    temp.get();
//    auto end1 = std::chrono::high_resolution_clock::now();
//    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);
//    std::cout << "Время шифрования: " << encryptTime.count() << " мс\n";
//
//// Дешифрование
//    auto start2 = std::chrono::high_resolution_clock::now();
//    context.decrypt(encryptedOutput, decryptedOutput).get();
//    auto end2 = std::chrono::high_resolution_clock::now();
//    auto decryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);
//    std::cout << "Время дешифрования: " << decryptTime.count() << " мс\n";
//
//// Проверяем размеры
//    if (std::filesystem::exists(encryptedOutput)) {
//        std::cout << "Размер зашифрованного файла: "
//                  << std::filesystem::file_size(encryptedOutput) << " байт\n";
//    }
//    if (std::filesystem::exists(decryptedOutput)) {
//        std::cout << "Размер дешифрованного файла: "
//                  << std::filesystem::file_size(decryptedOutput) << " байт\n";
//    }
//
//    std::byte poly{189};
//    INFO p = {poly};
//    bit_op::print_permissions(p);
//    auto u = GaloisFieldService::inverse(poly, AESmod);
//    bit_op::print_permissions({u});
//    bit_op::print_permissions({GaloisFieldService::multiply(poly, u, AESmod)});
//
//    RconGenerator generator(AESmod);
//    generator.print_Rcon();
    return 0;
}