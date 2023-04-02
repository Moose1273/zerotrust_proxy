#ifndef _TLSPROXY_H_
#define _TLSPROXY_H_
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <vector>
#include <cstring>
#include <iostream>
#include <unordered_set>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cJSON.h"
#include "../util.h"
#include "SPA_Proxy.h"
#define CA_CRT_PATH "./keys/ca.crt"
#define CLIENT_KEY_PATH "./keys/client.key"
#define CLIENT_CRT_PATH "./keys/client.crt"
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1

#pragma once
using namespace std;
class TLSProxyClient
{
public:
    TLSProxyClient(const std::string &serverAddr, int serverPort);
    ~TLSProxyClient();

    void TLSsetter(const std::string &serverAddr, int serverPort);

    // connect to TLS server
    bool connectToTLSServer();

    bool sendTLSData(const std::vector<char> &data);

    bool receiveTLSData(std::vector<char> &data);

    bool analyzeTLSpacket(char* buffer);

    //构造登录请求， 返回json
    int constructLoginRequest(std::vector<char> &data);
    //发送请求服务列表的request
    int sendServiceRequest();

    void setParses(char* gatewayIP, char* gatewayPort, char* hotp, char*hmac);

    vector<string> getParses();

    void closeConnection();

private:
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    SSL_CTX *m_sslContext = nullptr;
    SSL *m_ssl = nullptr;
    X509 *server_cert;
    vector<string> parses;
};

#endif/*include _TLSPROXY_H_*/