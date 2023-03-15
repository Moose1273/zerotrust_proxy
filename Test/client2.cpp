#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "SPA.h"
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "SPA.h"
#endif
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
using namespace std;
class SPAProxyClient
{
public:
    SPAProxyClient(const std::string &serverAddr, int serverPort) : m_serverAddr(serverAddr), m_serverPort(serverPort)
    {
#ifdef _WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0)
        {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
#endif
    }
    ~SPAProxyClient()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    // connect to UDP server
    bool connectToUDPServer()
    {
        m_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (m_socket == INVALID_SOCKET)
        {
            return false;
        }

        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(m_serverAddr.c_str());
        server.sin_port = htons(m_serverPort);

        if (connect(m_socket, (struct sockaddr *)&server, sizeof(server)) != 0)
        {
            return false;
        }

        return true;
    }
    
    //send&receive UDP data
    // bool sendUDPData(const std::vector<char> &data)
    // {
    //     int result = send(m_socket, data.data(), data.size(), 0);
    //     return result != SOCKET_ERROR;
    // }
    // bool receiveUDPData(std::vector<char> &data)
    // {
    //     char buffer[1024];
    //     int numBytes = recv(m_socket, buffer, sizeof(buffer), 0);
    //     if (numBytes == SOCKET_ERROR || numBytes == 0)
    //     {
    //         return false;
    //     }
    //     data.insert(data.end(), buffer, buffer + numBytes);
    //     return true;
    // }

    bool sendSPAData()
    {
        initialSPA(&spaInfo);
        int result = send(m_socket, (char*)&spaInfo, sizeof(SPA), 0);
        return result != SOCKET_ERROR;
    }

    bool receiveSPAData(std::vector<char> &data)
    {
        char buffer[1024];
        int numBytes = recv(m_socket, buffer, sizeof(buffer), 0);
        if (numBytes == SOCKET_ERROR || numBytes == 0)
        {
            return false;
        }
        data.insert(data.end(), buffer, buffer + numBytes);
        std::cout<<string(data.begin(), data.end())<<endl;
        return true;
    }

    void closeConnection()
    {
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
    }

private:
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    struct SPA spaInfo;
};

class TLSProxyClient
{
public:
    TLSProxyClient(const std::string &serverAddr, int serverPort) : m_serverAddr(serverAddr), m_serverPort(serverPort)
    {
#ifdef _WIN32
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0)
        {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }
#endif
    }
    ~TLSProxyClient()
    {
        SSL_CTX_free(m_sslContext);
        EVP_cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
    }

    // connect to TLS server
    bool connectToTLSServer()
    {
        m_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (m_socket == INVALID_SOCKET)
        {
            return false;
        }

        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(m_serverAddr.c_str());
        server.sin_port = htons(m_serverPort);

        if (connect(m_socket, (struct sockaddr *)&server, sizeof(server)) != 0)
        {
            return false;
        }
        SSL_load_error_strings();
        SSL_library_init();
        // 加载数字证书和私钥
        m_sslContext = SSL_CTX_new(TLS_client_method());
        SSL_CTX_use_certificate_file(m_sslContext, "client.crt", SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(m_sslContext, "client.key", SSL_FILETYPE_PEM);
        SSL_CTX_set_verify(m_sslContext, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        SSL_CTX_load_verify_locations(m_sslContext, "ca.crt", nullptr);
        if (m_sslContext == nullptr) {
            return false;
        }
        m_ssl = SSL_new(m_sslContext);
        if (m_ssl == nullptr) {
            return false;
        }
        SSL_set_fd(m_ssl, m_socket);

        // SSL 握手
        if (SSL_connect(m_ssl) <= 0) {
            cerr << "SSL handshake failed." << endl;
            SSL_free(m_ssl);
            close(m_socket);
            return 1;
        }

        // 获取服务器证书信息
        server_cert = SSL_get_peer_certificate(m_ssl);
        if (server_cert == nullptr) {
            cerr << "No server certificate provided." << endl;
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            close(m_socket);
            return 1;
        }
    
        // 验证服务器证书
        long verify_result = SSL_get_verify_result(m_ssl);
        if (verify_result != X509_V_OK)
        {
            cerr << "Server certificate verification failed: " << X509_verify_cert_error_string(verify_result) << endl;
            X509_free(server_cert);
            SSL_shutdown(m_ssl);
            SSL_free(m_ssl);
            close(m_socket);
            return 1;
        }
        // 发送客户端证书
        SSL_write(m_ssl, "Hello, server!", 14);
        return true;
    }

    bool sendTLSData(const std::vector<char> &data)
    {
        int result = SSL_write(m_ssl, data.data(), data.size());
        return result > 0;
    }

    bool receiveTLSData(std::vector<char> &data)
    {
        char buffer[1024];
        int numBytes = SSL_read(m_ssl, buffer, sizeof(buffer));
        if (numBytes <= 0)
        {
            return false;
        }
        data.insert(data.end(), buffer, buffer + numBytes);
        return true;
    }

    void closeConnection()
    {
        SSL_shutdown(m_ssl);
        X509_free(server_cert);
        //SSL_free(m_ssl);
#ifdef _WIN32
        closesocket(m_socket);
#else
        close(m_socket);
#endif
    }

private:
    std::string m_serverAddr;
    int m_serverPort;
    SOCKET m_socket;
    SSL_CTX* m_sslContext = nullptr;
    SSL* m_ssl = nullptr;
    X509* server_cert;
};

int main(int argc, char **argv)
{
    SPAProxyClient client("121.248.51.84", 7878);
    //TLSProxyClient tlsClient("121.248.51.84", 7878);
    if (!client.connectToUDPServer())
    {
        std::cerr << "Failed to connect to server." << std::endl;
        return 1;
    }
    // 构造请求
    //std::vector<char> request = {'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', '\r', '\n'};
    if (!client.sendSPAData())
    {
        std::cerr << "Failed to send data." << std::endl;
        client.closeConnection();
        return 1;
    }
    // 收到回复
    std::vector<char> response;
    while (client.receiveSPAData(response))
    {
        // Process the response data.
        std::cout << std::string(response.begin(), response.end()) << std::endl;
        std::cout<<response.size()<<endl;
        response.clear();
    }

    client.closeConnection();
    return 0;
}