#include <map>
#include <string>
#include <iostream>
using namespace std;

bool decode(const char *source, size_t size, std::string *target);
void encode(const char *source, size_t size, std::string *target);
bool decode4chars(const char *source, std::string *target);
void encode3bytes(const char *source, std::string *target, int append_num);


