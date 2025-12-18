#include "../include/RC6_from_igorek.h"
#include <stdexcept>
#include <random>
#include <cstring>
#include <algorithm>

std::vector<std::vector<uint8_t>> BlockUtils::splitIntoBlocks(
        const std::vector<uint8_t>& data, size_t blockSize) {
    if (blockSize == 0) {
        throw std::invalid_argument("Размер блока должен быть положительным");
    }
    if (blockSize > 255) {
        throw std::invalid_argument("Размер блока не может превышать 255 байт");
    }

    std::vector<std::vector<uint8_t>> blocks;
    for (size_t i = 0; i < data.size(); i += blockSize) {
        size_t end = std::min(i + blockSize, data.size());
        blocks.emplace_back(data.begin() + i, data.begin() + end);
    }

    return blocks;
}

std::vector<uint8_t> BlockUtils::joinBlocks(
        const std::vector<std::vector<uint8_t>>& blocks) {
    size_t totalSize = 0;
    for (const auto& block : blocks) {
        totalSize += block.size();
    }

    std::vector<uint8_t> result;
    result.reserve(totalSize);
    for (const auto& block : blocks) {
        result.insert(result.end(), block.begin(), block.end());
    }

    return result;
}

static std::vector<uint8_t> padZeros(const std::vector<uint8_t>& data, size_t paddingLength) {
    std::vector<uint8_t> result = data;
    result.insert(result.end(), paddingLength, 0);
    return result;
}

static std::vector<uint8_t> unpadZeros(const std::vector<uint8_t>& data) {
    size_t endIndex = data.size();
    while (endIndex > 0 && data[endIndex - 1] == 0) {
        endIndex--;
    }
    return std::vector<uint8_t>(data.begin(), data.begin() + endIndex);
}

static std::vector<uint8_t> padANSI_X923(const std::vector<uint8_t>& data, size_t paddingLength) {
    if (paddingLength == 0) return data;

    std::vector<uint8_t> result = data;
    result.insert(result.end(), paddingLength - 1, 0);
    result.push_back(static_cast<uint8_t>(paddingLength));
    return result;
}

static std::vector<uint8_t> unpadANSI_X923(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;

    uint8_t paddingLength = data.back();
    if (paddingLength == 0 || paddingLength > data.size()) {
        throw std::invalid_argument("Некорректная длина паддинга ANSI X.923");
    }

    // Проверяем, что все байты паддинга кроме последнего - нули
    for (size_t i = data.size() - paddingLength; i < data.size() - 1; i++) {
        if (data[i] != 0) {
            throw std::invalid_argument("Некорректный паддинг ANSI X.923");
        }
    }

    return std::vector<uint8_t>(data.begin(), data.end() - paddingLength);
}

static std::vector<uint8_t> padPKCS7(const std::vector<uint8_t>& data, size_t paddingLength) {
    if (paddingLength == 0) return data;

    std::vector<uint8_t> result = data;
    result.insert(result.end(), paddingLength, static_cast<uint8_t>(paddingLength));
    return result;
}

static std::vector<uint8_t> unpadPKCS7(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;

    uint8_t paddingLength = data.back();
    if (paddingLength == 0 || paddingLength > data.size()) {
        throw std::invalid_argument("Некорректная длина паддинга PKCS#7");
    }

    // Проверяем, что все байты паддинга равны длине паддинга
    for (size_t i = data.size() - paddingLength; i < data.size(); i++) {
        if (data[i] != paddingLength) {
            throw std::invalid_argument("Некорректный паддинг PKCS#7");
        }
    }

    return std::vector<uint8_t>(data.begin(), data.end() - paddingLength);
}

static std::vector<uint8_t> padISO_10126(const std::vector<uint8_t>& data, size_t paddingLength) {
    if (paddingLength == 0) return data;

    std::vector<uint8_t> result = data;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < paddingLength - 1; i++) {
        result.push_back(static_cast<uint8_t>(dis(gen)));
    }
    result.push_back(static_cast<uint8_t>(paddingLength));
    return result;
}

static std::vector<uint8_t> unpadISO_10126(const std::vector<uint8_t>& data) {
    if (data.empty()) return data;

    uint8_t paddingLength = data.back();
    if (paddingLength == 0 || paddingLength > data.size()) {
        throw std::invalid_argument("Некорректная длина паддинга ISO 10126");
    }

    return std::vector<uint8_t>(data.begin(), data.end() - paddingLength);
}

std::vector<uint8_t> BlockUtils::padData(const std::vector<uint8_t>& data,
                                         size_t blockSize,
                                         PaddingMode paddingMode) {
    if (blockSize == 0 || blockSize > 255) {
        throw std::invalid_argument("Недопустимый размер блока");
    }

    size_t paddingLength;
    if (data.size() % blockSize == 0) {
        paddingLength = blockSize;
    } else {
        paddingLength = blockSize - (data.size() % blockSize);
    }

    switch (paddingMode) {
        case PaddingMode::ZEROS:
            return padZeros(data, paddingLength);
        case PaddingMode::ANSI_X923:
            return padANSI_X923(data, paddingLength);
        case PaddingMode::PKCS7:
            return padPKCS7(data, paddingLength);
        case PaddingMode::ISO_10126:
            return padISO_10126(data, paddingLength);
        default:
            throw std::invalid_argument("Неподдерживаемый режим паддинга");
    }
}

std::vector<uint8_t> BlockUtils::unpadData(const std::vector<uint8_t>& data,
                                           PaddingMode paddingMode) {
    if (data.empty()) return data;

    switch (paddingMode) {
        case PaddingMode::ZEROS:
            return unpadZeros(data);
        case PaddingMode::ANSI_X923:
            return unpadANSI_X923(data);
        case PaddingMode::PKCS7:
            return unpadPKCS7(data);
        case PaddingMode::ISO_10126:
            return unpadISO_10126(data);
        default:
            throw std::invalid_argument("Неподдерживаемый режим паддинга");
    }
}

// ============================================================================
// Утилиты для работы с битами
// ============================================================================

std::vector<uint8_t> BitUtils::xorBytes(const std::vector<uint8_t>& a,
                                        const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Длины массивов должны совпадать");
    }

    std::vector<uint8_t> result;
    result.reserve(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result.push_back(a[i] ^ b[i]);
    }

    return result;
}

std::vector<uint8_t> BitUtils::randomBytes(size_t length) {
    std::vector<uint8_t> result;
    result.reserve(length);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < length; i++) {
        result.push_back(static_cast<uint8_t>(dis(gen)));
    }

    return result;
}

// ============================================================================
// Класс RC6
// ============================================================================

RC6::RC6(const std::vector<uint8_t>& key) {
    if (key.empty()) {
        throw std::invalid_argument("Ключ не может быть пустым");
    }

    S = keySchedule(key);
}

uint32_t RC6::rol(uint32_t x, uint32_t y) const {
    y = y % w;
    return ((x << y) | (x >> (w - y))) & (modulo - 1);
}

uint32_t RC6::ror(uint32_t x, uint32_t y) const {
    y = y % w;
    return ((x >> y) | (x << (w - y))) & (modulo - 1);
}

std::vector<uint32_t> RC6::keySchedule(const std::vector<uint8_t>& key) {
    size_t c = key.size() / 4;
    if (key.size() % 4 != 0) {
        c++;
    }
    if (c == 0) {
        c = 1;
    }

    // Дополняем ключ нулями до кратности 4
    std::vector<uint8_t> paddedKey = key;
    while (paddedKey.size() % 4 != 0) {
        paddedKey.push_back(0);
    }

    // Преобразуем ключ в массив 32-битных слов (little-endian)
    std::vector<uint32_t> L;
    L.reserve(c);
    for (size_t i = 0; i < paddedKey.size(); i += 4) {
        uint32_t word = 0;
        word |= static_cast<uint32_t>(paddedKey[i]);
        word |= static_cast<uint32_t>(paddedKey[i + 1]) << 8;
        word |= static_cast<uint32_t>(paddedKey[i + 2]) << 16;
        word |= static_cast<uint32_t>(paddedKey[i + 3]) << 24;
        L.push_back(word);
    }

    size_t t = 2 * r + 4;
    std::vector<uint32_t> S(t);
    S[0] = P32;
    for (size_t i = 1; i < t; i++) {
        S[i] = (S[i - 1] + Q32) % modulo;
    }

    uint32_t A = 0, B = 0;
    size_t i = 0, j = 0;
    size_t v = 3 * std::max(c, t);

    for (size_t k = 0; k < v; k++) {
        A = S[i] = rol((S[i] + A + B) % modulo, 3);
        B = L[j] = rol((L[j] + A + B) % modulo, (A + B) % w);
        i = (i + 1) % t;
        j = (j + 1) % c;
    }

    return S;
}

std::vector<uint8_t> RC6::encryptBlock(const std::vector<uint8_t>& block) {
    if (block.size() != blockSize) {
        throw std::invalid_argument("Размер блока должен быть 16 байт");
    }

    // Распаковываем блок в 4 32-битных слова (little-endian)
    uint32_t A = 0, B = 0, C = 0, D = 0;
    A |= static_cast<uint32_t>(block[0]);
    A |= static_cast<uint32_t>(block[1]) << 8;
    A |= static_cast<uint32_t>(block[2]) << 16;
    A |= static_cast<uint32_t>(block[3]) << 24;

    B |= static_cast<uint32_t>(block[4]);
    B |= static_cast<uint32_t>(block[5]) << 8;
    B |= static_cast<uint32_t>(block[6]) << 16;
    B |= static_cast<uint32_t>(block[7]) << 24;

    C |= static_cast<uint32_t>(block[8]);
    C |= static_cast<uint32_t>(block[9]) << 8;
    C |= static_cast<uint32_t>(block[10]) << 16;
    C |= static_cast<uint32_t>(block[11]) << 24;

    D |= static_cast<uint32_t>(block[12]);
    D |= static_cast<uint32_t>(block[13]) << 8;
    D |= static_cast<uint32_t>(block[14]) << 16;
    D |= static_cast<uint32_t>(block[15]) << 24;

    B = (B + S[0]) % modulo;
    D = (D + S[1]) % modulo;

    for (uint32_t i = 1; i <= r; i++) {
        uint32_t t = rol((B * (2 * B + 1)) % modulo, 5);
        uint32_t u = rol((D * (2 * D + 1)) % modulo, 5);

        A = (rol(A ^ t, u) + S[2 * i]) % modulo;
        C = (rol(C ^ u, t) + S[2 * i + 1]) % modulo;

        // Перестановка: A, B, C, D -> B, C, D, A
        uint32_t temp = A;
        A = B;
        B = C;
        C = D;
        D = temp;
    }

    A = (A + S[2 * r + 2]) % modulo;
    C = (C + S[2 * r + 3]) % modulo;

    // Упаковываем результат обратно в байты (little-endian)
    std::vector<uint8_t> result(blockSize);
    result[0] = static_cast<uint8_t>(A);
    result[1] = static_cast<uint8_t>(A >> 8);
    result[2] = static_cast<uint8_t>(A >> 16);
    result[3] = static_cast<uint8_t>(A >> 24);

    result[4] = static_cast<uint8_t>(B);
    result[5] = static_cast<uint8_t>(B >> 8);
    result[6] = static_cast<uint8_t>(B >> 16);
    result[7] = static_cast<uint8_t>(B >> 24);

    result[8] = static_cast<uint8_t>(C);
    result[9] = static_cast<uint8_t>(C >> 8);
    result[10] = static_cast<uint8_t>(C >> 16);
    result[11] = static_cast<uint8_t>(C >> 24);

    result[12] = static_cast<uint8_t>(D);
    result[13] = static_cast<uint8_t>(D >> 8);
    result[14] = static_cast<uint8_t>(D >> 16);
    result[15] = static_cast<uint8_t>(D >> 24);

    return result;
}

std::vector<uint8_t> RC6::decryptBlock(const std::vector<uint8_t>& block) {
    if (block.size() != blockSize) {
        throw std::invalid_argument("Размер блока должен быть 16 байт");
    }

    // Распаковываем блок в 4 32-битных слова (little-endian)
    uint32_t A = 0, B = 0, C = 0, D = 0;
    A |= static_cast<uint32_t>(block[0]);
    A |= static_cast<uint32_t>(block[1]) << 8;
    A |= static_cast<uint32_t>(block[2]) << 16;
    A |= static_cast<uint32_t>(block[3]) << 24;

    B |= static_cast<uint32_t>(block[4]);
    B |= static_cast<uint32_t>(block[5]) << 8;
    B |= static_cast<uint32_t>(block[6]) << 16;
    B |= static_cast<uint32_t>(block[7]) << 24;

    C |= static_cast<uint32_t>(block[8]);
    C |= static_cast<uint32_t>(block[9]) << 8;
    C |= static_cast<uint32_t>(block[10]) << 16;
    C |= static_cast<uint32_t>(block[11]) << 24;

    D |= static_cast<uint32_t>(block[12]);
    D |= static_cast<uint32_t>(block[13]) << 8;
    D |= static_cast<uint32_t>(block[14]) << 16;
    D |= static_cast<uint32_t>(block[15]) << 24;

    C = (C - S[2 * r + 3] + modulo) % modulo;
    A = (A - S[2 * r + 2] + modulo) % modulo;

    for (uint32_t i = r; i >= 1; i--) {
        // Обратная перестановка: B, C, D, A -> D, A, B, C
        uint32_t temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;

        uint32_t u = rol((D * (2 * D + 1)) % modulo, 5);
        uint32_t t = rol((B * (2 * B + 1)) % modulo, 5);

        C = (ror((C - S[2 * i + 1] + modulo) % modulo, t) ^ u);
        A = (ror((A - S[2 * i] + modulo) % modulo, u) ^ t);
    }

    D = (D - S[1] + modulo) % modulo;
    B = (B - S[0] + modulo) % modulo;

    // Упаковываем результат обратно в байты (little-endian)
    std::vector<uint8_t> result(blockSize);
    result[0] = static_cast<uint8_t>(A);
    result[1] = static_cast<uint8_t>(A >> 8);
    result[2] = static_cast<uint8_t>(A >> 16);
    result[3] = static_cast<uint8_t>(A >> 24);

    result[4] = static_cast<uint8_t>(B);
    result[5] = static_cast<uint8_t>(B >> 8);
    result[6] = static_cast<uint8_t>(B >> 16);
    result[7] = static_cast<uint8_t>(B >> 24);

    result[8] = static_cast<uint8_t>(C);
    result[9] = static_cast<uint8_t>(C >> 8);
    result[10] = static_cast<uint8_t>(C >> 16);
    result[11] = static_cast<uint8_t>(C >> 24);

    result[12] = static_cast<uint8_t>(D);
    result[13] = static_cast<uint8_t>(D >> 8);
    result[14] = static_cast<uint8_t>(D >> 16);
    result[15] = static_cast<uint8_t>(D >> 24);

    return result;
}

// ============================================================================
// Класс RC6Context
// ============================================================================

RC6Context::RC6Context(RC6& cipher, CipherMode mode, PaddingMode padding,
                       const std::optional<std::vector<uint8_t>>& iv)
        : cipher(cipher), mode(mode), padding(padding), blockSize(cipher.getBlockSize()),
          iv(iv), isFirstChunk(true) {
    validateParams();
    initState();
}

void RC6Context::validateParams() {
    if (mode != CipherMode::ECB && !iv.has_value()) {
        throw std::invalid_argument("IV is required for mode");
    }
    if (iv.has_value() && iv->size() != blockSize) {
        throw std::invalid_argument("IV length must match block size");
    }
}

void RC6Context::initState() {
    if (iv.has_value()) {
        stateVec = *iv;
    }
}

std::vector<uint8_t> RC6Context::incrementCounter(const std::vector<uint8_t>& counter) {
    std::vector<uint8_t> result = counter;
    for (int i = static_cast<int>(result.size()) - 1; i >= 0; i--) {
        if (result[i] == 0xFF) {
            result[i] = 0;
        } else {
            result[i]++;
            break;
        }
    }
    return result;
}

std::vector<uint8_t> RC6Context::generateDelta(const std::vector<uint8_t>& counter) {
    std::vector<uint8_t> result(counter.size());
    for (size_t i = 0; i < counter.size(); i++) {
        result[i] = static_cast<uint8_t>((counter[i] * 17 + i * 13) % 256);
    }
    return result;
}

std::vector<uint8_t> RC6Context::encryptChunk(const std::vector<uint8_t>& data, bool isLast) {
    std::vector<uint8_t> processedData = data;

    // Паддинг применяется только к последнему блоку
    if (isLast) {
        processedData = BlockUtils::padData(processedData, blockSize, padding);
    } else if (processedData.size() % blockSize != 0) {
        throw std::invalid_argument("Данные должны быть кратны размеру блока, если это не последний блок");
    }

    auto blocks = BlockUtils::splitIntoBlocks(processedData, blockSize);
    std::vector<std::vector<uint8_t>> processedBlocks;

    if (mode == CipherMode::ECB) {
        for (const auto& block : blocks) {
            processedBlocks.push_back(cipher.encryptBlock(block));
        }
    } else if (mode == CipherMode::CBC) {
        for (const auto& block : blocks) {
            auto x = BitUtils::xorBytes(block, stateVec);
            auto c = cipher.encryptBlock(x);
            processedBlocks.push_back(c);
            stateVec = c;
        }
    } else if (mode == CipherMode::PCBC) {
        for (const auto& block : blocks) {
            auto x = BitUtils::xorBytes(block, stateVec);
            auto c = cipher.encryptBlock(x);
            processedBlocks.push_back(c);
            stateVec = BitUtils::xorBytes(block, c);
        }
    } else if (mode == CipherMode::CFB) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto c = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(c);
            stateVec = c;
        }
    } else if (mode == CipherMode::OFB) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto c = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(c);
            stateVec = keystream;
        }
    } else if (mode == CipherMode::CTR) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto c = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(c);
            stateVec = incrementCounter(stateVec);
        }
    } else if (mode == CipherMode::RANDOM_DELTA) {
        for (const auto& block : blocks) {
            auto delta = generateDelta(stateVec);
            auto modified = BitUtils::xorBytes(stateVec, delta);
            auto ks = cipher.encryptBlock(modified);
            auto c = BitUtils::xorBytes(block, ks);
            processedBlocks.push_back(c);
            stateVec = incrementCounter(stateVec);
        }
    } else {
        throw std::invalid_argument("Unsupported mode");
    }

    return BlockUtils::joinBlocks(processedBlocks);
}

std::vector<uint8_t> RC6Context::decryptChunk(const std::vector<uint8_t>& data, bool isLast) {
    if (data.size() % blockSize != 0) {
        throw std::invalid_argument("Encrypted data must be multiple of block size");
    }

    auto blocks = BlockUtils::splitIntoBlocks(data, blockSize);
    std::vector<std::vector<uint8_t>> processedBlocks;

    if (mode == CipherMode::ECB) {
        for (const auto& block : blocks) {
            processedBlocks.push_back(cipher.decryptBlock(block));
        }
    } else if (mode == CipherMode::CBC) {
        for (const auto& block : blocks) {
            auto dec = cipher.decryptBlock(block);
            auto p = BitUtils::xorBytes(dec, stateVec);
            processedBlocks.push_back(p);
            stateVec = block;
        }
    } else if (mode == CipherMode::PCBC) {
        for (const auto& block : blocks) {
            auto dec = cipher.decryptBlock(block);
            auto p = BitUtils::xorBytes(dec, stateVec);
            processedBlocks.push_back(p);
            stateVec = BitUtils::xorBytes(p, block);
        }
    } else if (mode == CipherMode::CFB) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto p = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(p);
            stateVec = block;
        }
    } else if (mode == CipherMode::OFB) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto p = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(p);
            stateVec = keystream;
        }
    } else if (mode == CipherMode::CTR) {
        for (const auto& block : blocks) {
            auto keystream = cipher.encryptBlock(stateVec);
            auto p = BitUtils::xorBytes(block, keystream);
            processedBlocks.push_back(p);
            stateVec = incrementCounter(stateVec);
        }
    } else if (mode == CipherMode::RANDOM_DELTA) {
        for (const auto& block : blocks) {
            auto delta = generateDelta(stateVec);
            auto modified = BitUtils::xorBytes(stateVec, delta);
            auto ks = cipher.encryptBlock(modified);
            auto p = BitUtils::xorBytes(block, ks);
            processedBlocks.push_back(p);
            stateVec = incrementCounter(stateVec);
        }
    } else {
        throw std::invalid_argument("Unsupported mode");
    }

    auto result = BlockUtils::joinBlocks(processedBlocks);
    if (isLast) {
        result = BlockUtils::unpadData(result, padding);
    }
    return result;
}

