#include "LibFileStream.hpp" 
#include <iostream>

int main(void)
{
    fileStream<char> a;
    unsigned int b = 5, c = 3;
    a.open("testable.bin", 2, true);
    if(a.getError() != 0) { a.close(); return a.error; }
    a.writeBlock(&b, 1);
    a.writeBlock(&c, 1);
    //a.writeByFormat("%u|%u", b, c);
    a.close();
    b = 0; c = 0;
    a.open("testable.bin", 1, true);
    //a.getByFormat("%u|%u", &b, &c);
    int *bp = a.readBlock<int>(1);
    if(a.getError() != 0) { a.close(); return a.error; }
    int *cp = a.readBlock<int>(1);
    if(a.getError() != 0) { a.close(); return a.error; }
    a.close();
    std::cout << *bp << ":" << *cp << ".\n";
    
}