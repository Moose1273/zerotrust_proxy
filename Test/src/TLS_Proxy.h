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
#include <unordered_set>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cJSON.h"
#include "util.h"
#include "SPA_Proxy.h"
#define CA_CRT_PATH "./keys/ca.crt"
#define CLIENT_KEY_PATH "./keys/client_HB_Client_1145.key"
#define CLIENT_CRT_PATH "./keys/client_HB_Client_1145.crt"
typedef int SOCKET;

#pragma once
using namespace std;
class TLSProxyClient
{
public:
    TLSProxyClient();
    TLSProxyClient(const std::string &serverAddr, int serverPort);
    ~TLSProxyClient();

    void TLSsetter(const std::string &serverAddr, int serverPort);

    /*
        connect to TLS server
    */
    int connectToTLSServer();
    /*
        send encrypted data to TLS server
    */
    int sendTLSData(std::vector<char> &data);
    /*
        send data to TLS server
    */
    int sendData(std::vector<char> &data);
    /*
        recrive encrypted data afrom TLS server
    */
    int receiveTLSData(std::vector<char> &data);
    /*
        recrive data from TLS server
    */
    int receiveData(std::vector<char> &data);
    /*
        analyze TLS Data
    */
    int analyzeTLSpacket(char* buffer);

    //构造登录请求， 返回json
    int constructLoginRequest(std::vector<char> &data);
    //构造服务列表的请求， 返回json
    int constructServiceRequest(std::vector<char> &data);

    void setParses(char* gatewayIP, char* gatewayPort, char* hotp, char*hmac);

    vector<string> getParses();

    void closeConnection();

private:
    struct sockaddr_in server;
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    SSL_CTX *m_sslContext = nullptr;
    SSL *m_ssl = nullptr;
    X509 *server_cert;
    /*
        used for constructing spa packet
    */
    vector<string> parses;
};

#endif/*include _TLSPROXY_H_*/