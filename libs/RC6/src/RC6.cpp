#include "../include/RC6.h"


BOOSTED_INT RC6KeysGenerator::P_generator(size_t w) {
    auto q = (exp(1) - 2) * boost::multiprecision::cpp_dec_float_50 (BOOSTED_INT{2} << w);
    return round_to_boosted_int(q);
}

boost::multiprecision::cpp_dec_float_50 RC6KeysGenerator::golden_ratio() const {
    return (boost::multiprecision::sqrt(boost::multiprecision::cpp_dec_float_50(5)) + 1) / 2;
}

BOOSTED_INT RC6KeysGenerator::Q_generator(size_t w) {
    auto q= (golden_ratio() - 1) * boost::multiprecision::cpp_dec_float_50(BOOSTED_INT{2} << w);
    return round_to_boosted_int(q);
}

BOOSTED_INT RC6KeysGenerator::round_to_boosted_int(boost::multiprecision::cpp_dec_float_50 number) {
    auto s = boost::multiprecision::round(number);
    auto n = static_cast<BOOSTED_INT>(s);

    // ОШИБКА: if(n & 1 == 0) - приоритет операторов неверный!
    // Нужно: if((n & 1) == 0)
    if((n & 1) == 0) {  // ИСПРАВЛЕНО!
        if (number > s) {
            n += 1;
        } else {
            n -= 1;
        }
    }
    return n;
}

std::vector<INFO> RC6KeysGenerator::make_round_keys(const INFO &key, size_t amount_of_rounds) {
    BOOSTED_INT p = P_generator(w);
    BOOSTED_INT q = Q_generator(w);
    size_t u = w / 8;
    size_t c = b / u;
    if(b % u != 0) {
        c += 1;
    }
    std::vector<BOOSTED_INT> L(c);
    std::vector<BOOSTED_INT> key_b;
    std::vector<BOOSTED_INT> S(2 * amount_of_rounds+ 4);
    for(size_t i = 0; i < key.size(); ++i) {
        key_b.push_back(BOOSTED_INT{} | key[i]);
    }

    for(int i = (int)b - 1;i >= 0; --i) {
        L[i/u] = cycling_rotate_left(L[i / u], 8, 8) + key_b[i];
    }


    S[0] = p;
    for(size_t i = 1; i < S.size(); ++i) {
        S[i] = S[i-1] + q;
    }

    BOOSTED_INT A = 0;
    BOOSTED_INT B = 0;
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;
    size_t t = 2 * (amount_of_rounds + 1);
    for(; k < 3 * std::max(t, c); k++, i = (i + 1) % t, j = (j + 1) % c) {
        A = S[i] = cycling_rotate_left((A + B + S[i]), 3, 8);
        B = L[j] = cycling_rotate_left((A + B + L[j]), (A+B).convert_to<size_t>(), 8);

    }
    std::vector<std::vector<std::byte>> res(S.size());
    for (size_t i = 0; i < res.size(); ++i) {
        res[i] = convert_to_bytes_vector(S[i]);
    }
    return res;
}

RC6KeysGenerator::RC6KeysGenerator(size_t w, size_t b) : w(w), b(b) {}

BOOSTED_INT RC6KeysGenerator::cycling_rotate_left(const BOOSTED_INT &number, size_t shift, size_t width) {
    // Обработка крайних случаев
    if (width == 0) return 0;

    // Нормализуем сдвиг
    shift = shift % width;
    if (shift == 0) {
        // Обрезаем число до width бит
        BOOSTED_INT mask = (BOOSTED_INT(1) << width) - 1;
        return number & mask;
    }

    // Создаем маску
    BOOSTED_INT mask = (BOOSTED_INT(1) << width) - 1;

    // Берем только width бит из исходного числа
    BOOSTED_INT n = number & mask;

    // Циклический сдвиг влево
    // 1. Сдвигаем влево на shift
    BOOSTED_INT shifted = n << shift;

    // 2. Берем биты, которые "вышли" за границы width
    BOOSTED_INT overflow = shifted >> width;

    // 3. Обрезаем shifted до width бит
    shifted = shifted & mask;

    // 4. Добавляем overflow
    return (shifted | overflow) & mask;
}

BOOSTED_INT RC6KeysGenerator::cycling_rotate_right(const BOOSTED_INT &number, size_t shift, size_t width) {
    // Обработка крайних случаев
    if (width == 0) return 0;

    // Нормализуем сдвиг
    shift = shift % width;
    if (shift == 0) {
        // Обрезаем число до width бит
        BOOSTED_INT mask = (BOOSTED_INT(1) << width) - 1;
        return number & mask;
    }

    // Создаем маску только один раз
    BOOSTED_INT mask = (BOOSTED_INT(1) << width) - 1;

    // Берем только width бит из исходного числа
    BOOSTED_INT n = number & mask;

    // Циклический сдвиг вправо через выделение частей
    // 1. Берем младшие shift бит (они станут старшими)
    BOOSTED_INT lower_bits = n & ((BOOSTED_INT(1) << shift) - 1);

    // 2. Сдвигаем влево на (width - shift) позиций
    lower_bits = lower_bits << (width - shift);

    // 3. Берем старшие (width - shift) бит и сдвигаем вправо
    BOOSTED_INT upper_bits = n >> shift;

    // 4. Объединяем
    return (lower_bits | upper_bits) & mask;
}

std::vector<std::byte> RC6KeysGenerator::convert_to_bytes_vector(const BOOSTED_INT &block) {
    std::vector<std::byte> res;
    BOOSTED_INT copy_block(block);
    while(copy_block > 0) {
        res.push_back(std::byte{(copy_block & 0xFF).convert_to<std::byte>()});
        copy_block >>= 8;
    }
    std::reverse(res.begin(), res.end());
    return res;
}

boost::multiprecision::cpp_int RC6KeysGenerator::convert_to_cpp_int(const std::vector<std::byte> &block) {
    boost::multiprecision::cpp_int res;
    for(size_t i = 0; i < block.size(); ++i) {
        res |= block[i];
        if(i != block.size() - 1) {
            res <<= 8;
        }
    }
    return res;
}

RC6::RC6(const std::vector<std::byte> &key, size_t block_size, size_t number_rounds)
        : keys_generator(block_size * 2, key.size()),  // w = block_size * 2 (в битах)
          key{key}, amount_of_rounds{number_rounds}, w(block_size * 2) {

    // Проверка: block_size должен быть кратен 4 (т.к. 4 слова)
    if (block_size % 4 != 0) {
        throw std::invalid_argument("Block size must be multiple of 4 bytes");
    }

    // Вычисляем ожидаемый w (в битах) из block_size (в байтах)
    // block_size (байт) = 4 * (w/8) = w/2 байт
    // => w = block_size * 2 (бит)
    this->block_size = block_size;
    set_key(key);
}

void RC6::set_key(const std::vector<std::byte> &key) {
    this->key = key;
    S = keys_generator.make_round_keys(key, amount_of_rounds);
    S_b.clear();
    for(size_t i = 0; i < S.size(); ++i) {
        S_b.push_back(RC6KeysGenerator::convert_to_cpp_int(S[i]));
    }
}

size_t RC6::get_block_size() {
    return block_size;
}

size_t RC6::log2_w(size_t w) {
    if (w == 0) return 0;
    size_t result = 0;
    while ((1ULL << result) < w) {
        ++result;
    }
    // Проверяем, является ли w степенью двойки
    if ((1ULL << result) != w) {
        --result;  // Берем ближайшую меньшую степень двойки
    }
    return result;
}

std::vector<std::byte> RC6::decrypt(const INFO &data) {
    // Проверяем размер данных
    size_t expected_size = 4 * (w / 8); // 4 слова по w/8 байт каждое
    if (data.size() != expected_size) {
        throw std::invalid_argument("Неверный размер блока данных");
    }

    // Конвертируем данные в 4 слова A, B, C, D
    BOOSTED_INT mask = (BOOSTED_INT(1) << w) - 1;

    // Извлекаем слова из блока данных
    BOOSTED_INT A = 0, B = 0, C = 0, D = 0;

    // Преобразуем байты в слова
    size_t bytes_per_word = w / 8;
    for (size_t i = 0; i < bytes_per_word; ++i) {
        A = (A << 8) | BOOSTED_INT(data[i]);
        B = (B << 8) | BOOSTED_INT(data[i + bytes_per_word]);
        C = (C << 8) | BOOSTED_INT(data[i + 2 * bytes_per_word]);
        D = (D << 8) | BOOSTED_INT(data[i + 3 * bytes_per_word]);
    }

    // Применяем маску
    A &= mask;
    B &= mask;
    C &= mask;
    D &= mask;

    // Обратное финальное преобразование
    A = (A - S_b[2 * amount_of_rounds + 2]) & mask;
    C = (C - S_b[2 * amount_of_rounds + 3]) & mask;

    // Обратные раунды
    size_t lgw = log2_w(w);

    for (size_t i = amount_of_rounds; i >= 1; --i) {
        // Обратный циклический сдвиг слов
        BOOSTED_INT temp = D;
        D = C;
        C = B;
        B = A;
        A = temp;

        // Вычисляем t и u (такие же, как при шифровании)
        BOOSTED_INT t = (B * (2 * B + 1)) & mask;
        t = keys_generator.cycling_rotate_left(t, lgw, w);

        BOOSTED_INT u = (D * (2 * D + 1)) & mask;
        u = keys_generator.cycling_rotate_left(u, lgw, w);

        // Обратные преобразования
        C = (C - S_b[2 * i + 1]) & mask;
        C = keys_generator.cycling_rotate_right(C,
                                                static_cast<size_t>(t & mask), w) ^ u;

        A = (A - S_b[2 * i]) & mask;
        A = keys_generator.cycling_rotate_right(A,
                                                static_cast<size_t>(u & mask), w) ^ t;
    }

    // Обратное начальное преобразование
    D = (D - S_b[1]) & mask;
    B = (B - S_b[0]) & mask;

    // Формируем результат
    std::vector<std::byte> result(expected_size);

    // Преобразуем слова обратно в байты
    for (int i = bytes_per_word - 1; i >= 0; --i) {
        result[i] = std::byte(static_cast<unsigned char>((A >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + bytes_per_word] = std::byte(static_cast<unsigned char>((B >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + 2 * bytes_per_word] = std::byte(static_cast<unsigned char>((C >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + 3 * bytes_per_word] = std::byte(static_cast<unsigned char>((D >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
    }

    return result;
}

std::vector<std::byte> RC6::encrypt(const INFO &data) {
    // Проверяем размер данных
    size_t expected_size = 4 * (w / 8); // 4 слова по w/8 байт каждое
    if (data.size() != expected_size) {
        throw std::invalid_argument("Неверный размер блока данных");
    }

    // Конвертируем данные в 4 слова A, B, C, D
    BOOSTED_INT mask = (BOOSTED_INT(1) << w) - 1;

    // Извлекаем слова из блока данных
    BOOSTED_INT A = 0, B = 0, C = 0, D = 0;

    // Преобразуем байты в слова
    size_t bytes_per_word = w / 8;
    for (size_t i = 0; i < bytes_per_word; ++i) {
        A = (A << 8) | BOOSTED_INT(data[i]);
        B = (B << 8) | BOOSTED_INT(data[i + bytes_per_word]);
        C = (C << 8) | BOOSTED_INT(data[i + 2 * bytes_per_word]);
        D = (D << 8) | BOOSTED_INT(data[i + 3 * bytes_per_word]);
    }

    // Применяем маску
    A &= mask;
    B &= mask;
    C &= mask;
    D &= mask;

    // Начальное преобразование
    B = (B + S_b[0]) & mask;
    D = (D + S_b[1]) & mask;

    // Основные раунды
    size_t lgw = log2_w(w);

    for (size_t i = 1; i <= amount_of_rounds; ++i) {
        // Вычисляем t и u
        BOOSTED_INT t = (B * (2 * B + 1)) & mask;
        t = keys_generator.cycling_rotate_left(t, lgw, w);

        BOOSTED_INT u = (D * (2 * D + 1)) & mask;
        u = keys_generator.cycling_rotate_left(u, lgw, w);

        // Обновляем A и C
        BOOSTED_INT A_rot = keys_generator.cycling_rotate_left(A ^ t,
                                                               static_cast<size_t>(u & mask), w);
        A = (A_rot + S_b[2 * i]) & mask;

        BOOSTED_INT C_rot = keys_generator.cycling_rotate_left(C ^ u,
                                                               static_cast<size_t>(t & mask), w);
        C = (C_rot + S_b[2 * i + 1]) & mask;

        // Циклический сдвиг слов (A, B, C, D) = (B, C, D, A)
        BOOSTED_INT temp = A;
        A = B;
        B = C;
        C = D;
        D = temp;
    }

    // Финальное преобразование
    A = (A + S_b[2 * amount_of_rounds + 2]) & mask;
    C = (C + S_b[2 * amount_of_rounds + 3]) & mask;

    // Формируем результат
    std::vector<std::byte> result(expected_size);

    // Преобразуем слова обратно в байты
    for (int i = bytes_per_word - 1; i >= 0; --i) {
        result[i] = std::byte(static_cast<unsigned char>((A >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + bytes_per_word] = std::byte(static_cast<unsigned char>((B >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + 2 * bytes_per_word] = std::byte(static_cast<unsigned char>((C >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
        result[i + 3 * bytes_per_word] = std::byte(static_cast<unsigned char>((D >> (8 * (bytes_per_word - 1 - i))) & 0xFF));
    }

    return result;
}
