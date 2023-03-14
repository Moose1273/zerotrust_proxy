#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include<random>
#include <cstring>
#include <iostream>
#include "SPA.h"
using namespace std;

//获得当前设备IP地址
uint32_t getSourceIP() {
    //curl checkip.amazonaws.com --no-progress-meter
	//curl -L ip.tool.lu
	//curl https://api.ipify.org
	std::string cmdLine(R"("curl https://api.ipify.org")");
	char buffer[1024] = { '\0' };
	FILE* pf = NULL;
#ifdef _WIN32
    pf = _popen(cmdLine.c_str(), "r");
#else 
    pf = popen(cmdLine.c_str(), "r");
#endif
	if (NULL == pf) {
		printf("open pipe failed\n");
		return -1;
	}
	std::string ret;
	while (fgets(buffer, sizeof(buffer), pf)) {
		ret += buffer;
	}
#ifdef _WIN32
    _pclose(pf);
#else 
    pclose(pf);
#endif
	//ret.pop_back();
	cout << "ret is: " << ret <<"ret length is: " <<ret.length()<< endl;
	uint32_t iaddr = inet_addr(ret.c_str());
	uint32_t ans = htonl(iaddr);
	//std::cout << std::hex << ans << std::dec << std::endl;
	return ans;
}
int initialSPA(struct SPA* spa)
{
	spa->userID.bits[0] = 1234123412341234;
	spa->userID.bits[1] = 1234123412341234;
	spa->userID.bits[2] = 1234123412341234;
	spa->userID.bits[3] = 1234123412341234;
	spa->deviceID.bits[0] = 5678567856785678;
	spa->deviceID.bits[1] = 5678567856785678;
	spa->deviceID.bits[2] = 5678567856785678;
	spa->deviceID.bits[3] = 5678567856785678;
	spa->timeStamp = time(NULL);
	std::default_random_engine e;
	spa->nonce = e();
	spa->sourceIP = getSourceIP();
	spa->destPort = 8000;
	string name = "redis";
	strncpy(spa->name, name.c_str(), strlen(name.c_str())+1);
	string type = "HTTPS";
	strncpy(spa->type, type.c_str(), strlen(type.c_str()) + 1);
	return true;
}
