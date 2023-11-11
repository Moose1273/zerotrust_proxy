#ifndef _SPAPROXY_H_
#define _SPAPROXY_H_
#pragma once
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include<iostream>
#include<vector>
#include <unordered_set>
#include<cstring>
#include <random>
#include <ctime>
#include <vector>
#include <bitset>
#include "base64.h"
#include "util.h"
#include "cJSON.h"
#pragma once
//按32位对齐，否则会以64位对齐。spa大小为160位.
#pragma  pack(4)
 struct SPA
{
	uint32_t ip_address;							//源IP
	uint64_t timestamp;								//时间戳
	uint32_t random_num;						    //随机数
	uint32_t message_type;					        //消息类型
	uint32_t  default_value[3];       			    //缺省值,default_value的第一位需要写tls证书的ID
	std::bitset<256> userID;						//用户ID
	std::bitset<256> deviceID;						//设备ID
	std::byte HOTP[32];							    //HOTP,基于HMAC的一次性密码
	std::byte hmac[32];							    //HMAC
};

typedef int SOCKET;
using namespace std;
class SPAProxyClient
{
public:
    SPAProxyClient();
    SPAProxyClient(const std::string &serverAddr, int serverPort);

    ~SPAProxyClient();

    // connect to UDP server
    int connectToSPAServer();

    //initial and send SPA data packet
    int initialSPA(std::string hotp = nullptr, std::string hmac = nullptr);

    int sendSPAData();

    int receiveSPAData(std::vector<char> &data);

    int analyzeSPApacket(char* buffer);

    void closeConnection();

private:
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    struct SPA spaInfo;
    struct sockaddr_in server;
};

#endif/*include _SPAPROXY_H_*/