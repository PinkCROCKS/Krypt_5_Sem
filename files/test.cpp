#include "../TestSymmetricContext.h"

int main(){
    TestSymmetricContext tester;
    tester.testAllModes();
    tester.testAllPaddingModes();
    tester.testFileEncryption("image.jpg");
    return 0;
}