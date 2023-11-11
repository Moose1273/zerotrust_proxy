#include "base64.h"
 
char table[64] = {
    'A','B','C','D','E','F','G','H',
    'I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X',
    'Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3',
    '4','5','6','7','8','9','+','/'
};
 
std::map<char, char> idx_table {
    {'A', 0}, {'B', 1}, {'C', 2}, {'D', 3}, {'E', 4}, {'F', 5}, {'G', 6}, {'H', 7},
    {'I', 8}, {'J', 9}, {'K', 10}, {'L', 11}, {'M', 12}, {'N', 13}, {'O', 14}, {'P', 15},
    {'Q', 16}, {'R', 17}, {'S', 18}, {'T', 19}, {'U', 20}, {'V', 21}, {'W', 22}, {'X', 23},
    {'Y', 24}, {'Z', 25}, {'a', 26}, {'b', 27}, {'c', 28}, {'d', 29}, {'e', 30}, {'f', 31},
    {'g', 32}, {'h', 33}, {'i', 34}, {'j', 35}, {'k', 36}, {'l', 37}, {'m', 38}, {'n', 39},
    {'o', 40}, {'p', 41}, {'q', 42}, {'r', 43}, {'s', 44}, {'t', 45}, {'u', 46}, {'v', 47},
    {'w', 48}, {'x', 49}, {'y', 50}, {'z', 51}, {'0', 52}, {'1', 53}, {'2', 54}, {'3', 55},
    {'4', 56}, {'5', 57}, {'6', 58}, {'7', 59}, {'8', 60}, {'9', 61}, {'+', 62}, {'/', 63}
};
 
void encode3bytes(const char *source, std::string *target, int append_num = 3) {
    uint8_t first = *source;
    target->push_back(table[first >> 2]);
    uint8_t second = *(source + 1);
    char tmp = ((first & 0x03) << 4) | (second >> 4);
    target->push_back(table[tmp]);
    if (--append_num == 0) { target->append("=="); return; }
    uint8_t third = *(source + 2);
    tmp = ((second & 0x0f) << 2) | (third >> 6);
    target->push_back(table[tmp]);
    if (--append_num == 0) { target->append("="); return; }
    target->push_back(table[third & 0x3f]);
}
 
bool decode4chars(const char *source, std::string *target) {
    auto it = idx_table.find(*source);
    if (it == idx_table.end()) { return false; }
    char first = it->second;
    it = idx_table.find(*(source + 1));
    if (it == idx_table.end()) { return false; }
    char second = it->second;
    char tmp = (first << 2) | (second >> 4);
    target->push_back(tmp);
    tmp = *(source + 2);
    if (tmp == '=') { return true; }
    it = idx_table.find(tmp);
    if (it == idx_table.end()) { return false; }
    char third = it->second;
    tmp = ((second & 0x0f) << 4) | (third >> 2);
    target->push_back(tmp);
    tmp = *(source + 3);
    if (tmp == '=') { return true; }
    it = idx_table.find(tmp);
    if (it == idx_table.end()) { return false; }
    char fourth = it->second;
    tmp = (third << 6) | fourth;
    target->push_back(tmp);
    return true;
}
 
 
void encode(const char *source, size_t size, std::string *target) {
    if (!size) { return; }
    target->reserve(size / 3 + size + 3);
    if (size <= 3) { return encode3bytes(source, target, size); }
    size_t i = 0;
    for (; i <= size - 3; i += 3) {
        encode3bytes(source + i, target);
    }
    if (i < size) { encode3bytes(source + i, target, size - i); }
}
 
bool decode(const char *source, size_t size, std::string *target) {
    if (size == 0 || (size & 3) > 0) { return size == 0; }
    target->reserve(size);
    for (size_t i = 0; i < size; i += 4) {
        if (!decode4chars(source + i, target)) { return false; }
    }
    return true;
}

// https://datatracker.ietf.org/doc/html/rfc4648#section-10
std::string test_cases[7] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
std::string test_encodes[7] = {"Y74ql4I+vTtfOendVb45mUY8DlgYgJy/DWeiLkl98Qo=", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
 
// int awe() {
//     std::string encoded;
//     for (int i = 0; i < 7; ++i) {
//         encoded.clear();
//         encode(test_cases[i].c_str(), test_cases[i].size(), &encoded);
//         if (encoded != test_encodes[i]) {
//             std::cout << "encode failure for:" << i << std::endl;
//         }
//     }
//     std::string decoded;
//     for (int i = 0; i < 7; ++i) {
//         decoded.clear();
//         decode(test_encodes[i].c_str(), test_encodes[i].size(), &decoded);
//         if (decoded != test_cases[i]) {
//             std::cout << "decode failure for:" << i << std::endl;
//         }
// 		std::cout<<decoded<<endl;
//     }
//     std::cout << "test ok" << std::endl;
//     return 0;
// }