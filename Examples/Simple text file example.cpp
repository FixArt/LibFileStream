#include "LibFileStream.hpp"
#include <iostream>

int main()
{
    fileStream<char> test;
    test.open("testable.txt", 1);
    if(test.error != 0) { test.close(); return 1; }
    char* testable = test.getFile<char>();
    if(test.error != 0) { test.close(); return 1; }
    std::cout << testable << "\n";
    delete[] testable;
    test.close();
}
