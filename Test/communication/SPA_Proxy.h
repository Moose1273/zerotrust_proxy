#ifndef _SPAPROXY_H_
#define _SPAPROXY_H_
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
#include "cJSON.h"
#include <random>
#include <ctime>
#include <vector>
#include <bitset>

#pragma once
#pragma pack (1)
 struct SPA
{
	uint32_t ip_address;							//源IP
	uint64_t timestamp;								//时间戳
	uint32_t random_num;						    //随机数
	uint32_t message_type;					        //消息类型
	uint32_t  default_value[3];       			    //缺省值
	std::bitset<256> userID;						//用户ID
	std::bitset<256> deviceID;						//设备ID
	std::bitset<256> HOTP;							//HOTP,基于HMAC的一次性密码
	std::bitset<256> hmac;							//HMAC
};

typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
using namespace std;
class SPAProxyClient
{
public:
    SPAProxyClient(const std::string &serverAddr, int serverPort);

    ~SPAProxyClient();

    // connect to UDP server
    bool connectToSPAServer();

    // send&receive UDP data
    //  bool sendUDPData(const std::vector<char> &data)
    //  {
    //      int result = send(m_socket, data.data(), data.size(), 0);
    //      return result != SOCKET_ERROR;
    //  }
    //  bool receiveUDPData(std::vector<char> &data)
    //  {
    //      char buffer[1024];
    //      int numBytes = recv(m_socket, buffer, sizeof(buffer), 0);
    //      if (numBytes == SOCKET_ERROR || numBytes == 0)
    //      {
    //          return false;
    //      }
    //      data.insert(data.end(), buffer, buffer + numBytes);
    //      return true;
    //  }

    //initial and send SPA data packet
    int initialSPA(const char* hotp = nullptr, const char* hmac = nullptr);

    bool sendSPAData();

    bool receiveSPAData(std::vector<char> &data);

    bool analyzeSPApacket(char* buffer);

    void closeConnection();

private:
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    struct SPA spaInfo;
};

#endif/*include _SPAPROXY_H_*/