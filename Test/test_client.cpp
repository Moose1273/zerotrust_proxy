#include<cstring>
#include <iostream>
#include <bitset>
using namespace std;


int main()
{
    const char* s = "01100101";
    std::bitset<32> b ;
    for (int i = 0; i < strlen(s); i++) {
        if (s[i] == '1') {
            b.set(strlen(s) - 1 - i); // 将第i位设置为1
        }
    }

    cout<<" "<<b<<endl;
    return 0;
}