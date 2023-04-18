#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 获取本机的IPv4地址
std::string get_local_ipv4() {
    std::string ip;

    // Windows系统
#ifdef _WIN32
    // 执行ipconfig命令，并获取命令输出
    FILE* fp = _popen("ipconfig | findstr /i \"IPv4\"", "r");
    if (fp != nullptr) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            char* pos = strstr(buffer, "IPv4");
            if (pos != nullptr) {
                ip = pos + strlen("IPv4 Address. . . . . . . . . . . :");
                ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
                break;
            }
        }
        _pclose(fp);
    }

    // Linux系统
#else
    // 执行ip命令，并获取命令输出
    FILE* fp = popen("ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1", "r");
    if (fp != nullptr) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            ip = buffer;
            ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
            break;
        }
        pclose(fp);
    }
#endif

    return ip;
}

int main() {
    std::string ipv4 = get_local_ipv4();
    const char* ip = ipv4.c_str();
    std::cout << "Local IPv4: " << ip << std::endl;
    return 0;
}
