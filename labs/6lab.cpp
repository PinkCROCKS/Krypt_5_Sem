#include "../libs/RC6/include/RC6.h"
int main(){
    // Тестовый блок должен быть 32 байта (4 * 8 байт)
    std::vector<std::byte> data{
            std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0a}, std::byte{0x0b},
            std::byte{0x0c}, std::byte{0x0d}, std::byte{0x0e}, std::byte{0x0f}
    };
    std::vector<std::byte> key = {
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
    RC6 rc(key2, 32, 20);
//    auto y = rc.encrypt(data);
//    auto t = rc.decrypt(y);
//    bit_op::print_permissions(data);
//    bit_op::print_permissions(t);

    INFO testIV = {std::byte{165}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
                   std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF}};
    std::optional<INFO> t(testIV);
    std::shared_ptr<SymmetricAlgorithm> y = std::make_shared<RC6>(rc);
    SymmetricEncryptingContext context(Random_Delta, ISO_10126, t, y);
    std::filesystem::path inputPath = "opu.mp4";
    std::filesystem::path encryptedOutput = inputPath.stem().string() + "_encrypted.bin";
    std::filesystem::path decryptedOutput = inputPath.stem().string() + "_decrypted" + inputPath.extension().string();
    uintmax_t originalSize = std::filesystem::file_size(inputPath);
    std::cout << "Размер файла: " << originalSize << " байт ("
              << originalSize / 1024 / 1024 << " MB)\n";

// Шифрование
    auto start1 = std::chrono::high_resolution_clock::now();
    auto temp = context.encrypt(inputPath, encryptedOutput);
    temp.get();
    auto end1 = std::chrono::high_resolution_clock::now();
    auto encryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1);
    std::cout << "Время шифрования: " << encryptTime.count() << " мс\n";

// Дешифрование
    auto start2 = std::chrono::high_resolution_clock::now();
    context.decrypt(encryptedOutput, decryptedOutput).get();
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