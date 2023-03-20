//#include "SPA2controller.cpp"
//#include <boost/asio.hpp>
// #ifdef _WIN32
// 	#include <WinSock2.h>
// 	#pragma comment(lib, "ws2_32.lib")
// #else 
// 	#include <sys/socket.h>
// 	#include <arpa/inet.h>
// #endif
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
using namespace std;
#define MAX_IP_LEN 64

const char* GET_IP_CMD = "curl -s https://api.ipify.org";

// 获取本地公网 IP 地址
uint32_t getSourceIP() {

	char cmd_output[MAX_IP_LEN];
	memset(cmd_output, 0, sizeof(cmd_output));

	FILE* pf = NULL;
#ifdef _WIN32
    pf = _popen(GET_IP_CMD, "r");
#else 
    pf = popen(GET_IP_CMD, "r");
#endif
	if (NULL == pf) {
		printf("open pipe failed\n");
		return -1;
	}
	fgets(cmd_output, MAX_IP_LEN, pf);
#ifdef _WIN32
    _pclose(pf);
#else 
    pclose(pf);
#endif
	
	uint32_t iaddr = inet_addr(cmd_output);
	uint32_t ipAddr = htonl(iaddr);
	//std::cout << std::hex << ans << std::dec << std::endl;
	cout<<ipAddr<<endl;
	return ipAddr;
}

int main() {
    getSourceIP();
	cout<<"hello world!"<<endl;
    return 0;
}