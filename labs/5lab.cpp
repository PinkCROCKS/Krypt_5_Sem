//
// Created by Ярослав on 18.12.2025.
//

#include "../libs/RC4/include/RC4.h"

int main(){
    INFO data{std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
              std::byte{0x44}, std::byte{0x55}, std::byte{0x66}, std::byte{0x77},
              std::byte{0x88}, std::byte{0x99}, std::byte{0xaa}, std::byte{0xbb},
              std::byte{0xcc},std::byte{0xdd}, std::byte{0xee}, std::byte{0xff}};
    RC4 rc{data};
    std::filesystem::path inputPath = "opu.mp4";
    std::filesystem::path encryptedOutput = inputPath.stem().string() + "_encrypted.bin";
    std::filesystem::path decryptedOutput = inputPath.stem().string() + "_decrypted" + inputPath.extension().string();
    uintmax_t originalSize = std::filesystem::file_size(inputPath);
    std::cout << "Размер файла: " << originalSize << " байт ("
              << originalSize / 1024 / 1024 << " MB)\n";

// Шифрование
    auto start1 = std::chrono::high_resolution_clock::now();
    rc.encrypt(inputPath, encryptedOutput);
    auto end1 = std::chrono::high_resolution_clock::now();
    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);
    std::cout << "Время шифрования: " << encryptTime.count() << " мс\n";

// Дешифрование
    auto start2 = std::chrono::high_resolution_clock::now();
    rc.decrypt(encryptedOutput, decryptedOutput);
    auto end2 = std::chrono::high_resolution_clock::now();
    auto decryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);
    std::cout << "Время дешифрования: " << decryptTime.count() << " мс\n";

// Проверяем размеры
    if (std::filesystem::exists(encryptedOutput)) {
        std::cout << "Размер зашифрованного файла: "
                  << std::filesystem::file_size(encryptedOutput) << " байт\n";
    }
    if (std::filesystem::exists(decryptedOutput)) {
        std::cout << "Размер дешифрованного файла: "
                  << std::filesystem::file_size(decryptedOutput) << " байт\n";
    }

    return 0;
}
