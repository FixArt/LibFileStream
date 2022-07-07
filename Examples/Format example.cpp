#include "LibFileStream.hpp" 
#include <iostream>

int main(void)
{
    fileStream<char> a;
    unsigned int b = 5, c = 3;
    a.open("testable.txt", 2, false);
    if(a.getError() != 0) { a.close(); return a.error; }
    a.writeByFormat("%u:%u", b, c);
    if(a.getError() != 0) { a.close(); return a.error; }
    a.close();
    b = 0; c = 0;
    a.open("testable.txt", 1, false);
    a.getByFormat("%u:%u", &b, &c);
    if(a.getError() != 0) { a.close(); return a.error; }
    a.close();
    std::cout << b << ":" << c << ".\n";
}
