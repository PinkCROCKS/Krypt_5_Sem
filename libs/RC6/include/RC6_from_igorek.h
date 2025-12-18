
#ifndef RC6_H
#define RC6_H

#include <vector>
#include <cstdint>
#include <string>
#include <optional>
#include <cstddef>

// Режимы шифрования
enum class CipherMode {
    ECB,
    CBC,
    PCBC,
    CFB,
    OFB,
    CTR,
    RANDOM_DELTA
};

// Режимы паддинга
enum class PaddingMode {
    ZEROS,
    ANSI_X923,
    PKCS7,
    ISO_10126
};

// Утилиты для работы с блоками
namespace BlockUtils {
    std::vector<std::vector<uint8_t>> splitIntoBlocks(const std::vector<uint8_t>& data, size_t blockSize);
    std::vector<uint8_t> joinBlocks(const std::vector<std::vector<uint8_t>>& blocks);
    std::vector<uint8_t> padData(const std::vector<uint8_t>& data, size_t blockSize, PaddingMode paddingMode);
    std::vector<uint8_t> unpadData(const std::vector<uint8_t>& data, PaddingMode paddingMode);
}

// Утилиты для работы с битами
namespace BitUtils {
    std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);
    std::vector<uint8_t> randomBytes(size_t length);
}

// Класс RC6
class RC6 {
public:
    explicit RC6(const std::vector<uint8_t>& key);

    size_t getBlockSize() const { return blockSize; }

    std::vector<uint8_t> encryptBlock(const std::vector<uint8_t>& block);
    std::vector<uint8_t> decryptBlock(const std::vector<uint8_t>& block);

private:
    static constexpr uint32_t w = 32;           // размер слова в битах
    static constexpr uint32_t r = 20;           // количество раундов
    static constexpr uint32_t modulo = 0x100000000ULL;  // 2^32
    static constexpr size_t blockSize = 16;     // 128 бит

    static constexpr uint32_t P32 = 0xB7E15163;
    static constexpr uint32_t Q32 = 0x9E3779B9;

    std::vector<uint32_t> S;  // Расширенный ключ

    uint32_t rol(uint32_t x, uint32_t y) const;
    uint32_t ror(uint32_t x, uint32_t y) const;
    std::vector<uint32_t> keySchedule(const std::vector<uint8_t>& key);
};

// Контекст шифрования RC6
class RC6Context {
public:
    RC6Context(RC6& cipher, CipherMode mode, PaddingMode padding,
               const std::optional<std::vector<uint8_t>>& iv = std::nullopt);

    std::vector<uint8_t> encryptChunk(const std::vector<uint8_t>& data, bool isLast = false);
    std::vector<uint8_t> decryptChunk(const std::vector<uint8_t>& data, bool isLast = false);

private:
    RC6& cipher;
    CipherMode mode;
    PaddingMode padding;
    size_t blockSize;
    std::optional<std::vector<uint8_t>> iv;

    std::vector<uint8_t> stateVec;
    bool isFirstChunk;

    void validateParams();
    void initState();
    std::vector<uint8_t> incrementCounter(const std::vector<uint8_t>& counter);
    std::vector<uint8_t> generateDelta(const std::vector<uint8_t>& counter);
};

#endif // RC6_H
