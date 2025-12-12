#include "../../RSA/include/RSA.h"
#include <iostream>
#include <chrono>
#include <fstream>

namespace fs = std::filesystem;


int main() {
    // Переменная с именем файла - можно легко менять
    std::string input_filename = "test.mp4";

    std::cout << "=== Тестирование RSA шифрования/дешифрования ===" << std::endl;
    std::cout << "Файл: " << input_filename << std::endl;

    // Проверяем существование файла
    if (!fs::exists(input_filename)) {
        std::cerr << "Ошибка: Файл " << input_filename << " не найден!" << std::endl;
        return 1;
    }

    std::cout << "Размер файла: " << fs::file_size(input_filename) << " байт" << std::endl;
    std::cout << "Расширение: " << fs::path(input_filename).extension() << std::endl;

    try {
        std::cout << "\nИнициализация RSA..." << std::endl;
        auto rsa_start = std::chrono::high_resolution_clock::now();
        RSA rsa(millerRabinTest, 0.99999, 1024);
        auto rsa_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - rsa_start);
        std::cout << "Генерация ключей заняла: " << rsa_duration.count() << " мс" << std::endl;
        std::cout << "\nНачало шифрования файла..." << std::endl;
        auto start_encrypt = std::chrono::high_resolution_clock::now();

        std::optional<fs::path> encrypt_output = std::nullopt; // Автоматическое имя
        auto encrypt_future = rsa.encrypt(input_filename);
        encrypt_future.get();

        auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start_encrypt);
        fs::path input_path(input_filename);
        std::string encrypted_filename = input_path.stem().string() + "_encrypted" + input_path.extension().string();
        if (!fs::exists(encrypted_filename)) {
            std::cerr << "Ошибка: Зашифрованный файл не создан!" << std::endl;
            return 1;
        }

        std::cout << "Зашифрованный файл: " << encrypted_filename << std::endl;
        std::cout << "Размер зашифрованного файла: " << fs::file_size(encrypted_filename) << " байт" << std::endl;
        std::cout << "Расширение зашифрованного файла: " << fs::path(encrypted_filename).extension() << std::endl;
        std::cout << "\nНачало дешифрования файла..." << std::endl;
        auto start_decrypt = std::chrono::high_resolution_clock::now();

        std::optional<fs::path> decrypt_output = std::nullopt; // Автоматическое имя
        auto decrypt_future = rsa.decrypt(encrypted_filename);
        decrypt_future.get();

        auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start_decrypt);
        std::string decrypted_filename = input_path.stem().string() + "_encrypted_decrypted" + input_path.extension().string();


        std::cout << "Расшифрованный файл: " << decrypted_filename << std::endl;
        std::cout << "Размер расшифрованного файла: " << fs::file_size(decrypted_filename) << " байт" << std::endl;
        std::cout << "Расширение расшифрованного файла: " << fs::path(decrypted_filename).extension() << std::endl;
        std::cout << "\n=== РЕЗУЛЬТАТЫ ===" << std::endl;
        std::cout << "Время генерации ключей: " << rsa_duration.count() << " мс" << std::endl;
        std::cout << "Время шифрования файла: " << encrypt_duration.count() << " мс" << std::endl;
        std::cout << "Время дешифрования файла: " << decrypt_duration.count() << " мс" << std::endl;
        std::cout << "Общее время: " << (rsa_duration + encrypt_duration + decrypt_duration).count() << " мс" << std::endl;
        std::cout << "\n=== ПРОВЕРКА РАСШИРЕНИЙ ===" << std::endl;
        std::cout << "Исходный файл: " << input_path.extension() << std::endl;
        std::cout << "Зашифрованный файл: " << fs::path(encrypted_filename).extension() << std::endl;
        std::cout << "Расшифрованный файл: " << fs::path(decrypted_filename).extension() << std::endl;

        if (input_path.extension() == fs::path(encrypted_filename).extension() &&
            input_path.extension() == fs::path(decrypted_filename).extension()) {
            std::cout << "✓ Расширения всех файлов совпадают!" << std::endl;
        } else {
            std::cout << "✗ Расширения файлов не совпадают!" << std::endl;
        }
        std::cout << "\n=== ПРОИЗВОДИТЕЛЬНОСТЬ ===" << std::endl;
        double original_size_kb = fs::file_size(input_filename) / 1024.0;
        double encrypt_speed = original_size_kb / (encrypt_duration.count() / 1000.0);
        double decrypt_speed = original_size_kb / (decrypt_duration.count() / 1000.0);

        std::cout << "ВРЕМЯ шифрования: " << encrypt_duration.count() / 1000.0 << std::endl;
        std::cout << "ВРЕМЯ дешифрования: " << decrypt_duration.count() / 1000.0 << std::endl;

        std::cout << "Скорость шифрования: " << encrypt_speed << " КБ/с" << std::endl;
        std::cout << "Скорость дешифрования: " << decrypt_speed << " КБ/с" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nТестирование завершено успешно!" << std::endl;
    INFO data{std::byte{113}, std::byte{97}, std::byte{25}, std::byte{224}, std::byte{113},
              std::byte{97}, std::byte{201}, std::byte{53}};

    return 0;
}