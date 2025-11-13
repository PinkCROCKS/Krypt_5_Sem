#include "TestSymmetricContext.h"

int main(){
    TestSymmetricContext tester;

    // Тестирование всех режимов шифрования
    tester.testAllModes();

    // Тестирование всех методов паддинга
    tester.testAllPaddingModes();

    // Тестирование файлового шифрования
    tester.testFileEncryption("image.jpg");

    return 0;
}