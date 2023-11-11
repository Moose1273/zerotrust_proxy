#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <random>
#include <cstring>
#include <iostream>
#include "SPA.h"
using namespace std;
#define MAX_IP_LEN 64
const char *GET_IP_CMD = "curl -s https://api.ipify.org";
// 获得当前设备IP地址
bool initialSPA(struct SPA *spa)
{
	// initial userID
	
	// initial deviceID

	// initial timestamp;
	spa->timestamp = time(NULL);

	// initial random_num;
	std::default_random_engine e;
	spa->random_num = e();

	// initial ip_address;
	char cmd_output[MAX_IP_LEN];
	memset(cmd_output, 0, sizeof(cmd_output));

	FILE *pf = NULL;
#ifdef _WIN32
	pf = _popen(GET_IP_CMD, "r");
#else
	pf = popen(GET_IP_CMD, "r");
#endif
	if (NULL == pf)
	{
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
	spa->ip_address = ipAddr;

	// initial message_type

	// initial default_value


	// initial HOTP


	// initial hmac


	string name = "service_name";
	strncpy(spa->name, name.c_str(), strlen(name.c_str()) + 1);
	string type = "service_type";
	strncpy(spa->type, type.c_str(), strlen(type.c_str()) + 1);
	return true;
}
