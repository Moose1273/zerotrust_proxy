#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "util.h"
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "communication/SPA_Proxy.h"
#include "communication/TLS_Proxy.h"
#endif
#define CA_CRT_PATH "./keys/ca.crt"
#define CLIENT_KEY_PATH "./keys/client.key"
#define CLIENT_CRT_PATH "./keys/client.crt"
typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
using namespace std;

int main(int argc, char **argv)
{
    // 向controller发起SPA请求
    SPAProxyClient client("121.248.51.84", 7878);
    bool status = client.connectToSPAServer();
    if (!status)
    {
        std::cerr << "Failed to connect to server." << std::endl;
        return -1;
    }
    // cout<<status<<endl;
    // 构造请求
    client.initialSPA();
    if (!client.sendSPAData())
    {
        std::cerr << "Failed to send data." << std::endl;
        client.closeConnection();
        return -1;
    }
    // 收到SPA回复
    std::vector<char> response;
    if (!client.receiveSPAData(response))
    {
        std::cout << "Failed to receive SPAData" << std::endl;
        response.clear();
        client.closeConnection();
        return -1;
    }
    // Process the response data.
    std::cout << std::string(response.begin(), response.end()) << std::endl;
    // std::cout << response.size() << endl;
    response.clear();
    client.closeConnection();

    // 向controller发起TLS请求
    TLSProxyClient tlsClient("121.248.51.84", 7878);
    bool status = tlsClient.connectToTLSServer();
    if (!status)
    {
        std::cerr << "Failed to connect to server." << std::endl;
        return -1;
    }

    std::vector<char> log_req;
    tlsClient.constructLoginRequest(log_req);
    if (!tlsClient.sendTLSData(log_req))
    {
        cerr << "send TLS log_req failed" << endl;
        tlsClient.closeConnection();
        return -1;
    }
    cout << "already sent tls log_req!" << endl;

    // 接收login响应
    std::vector<char> response;
    if (!tlsClient.receiveTLSData(response))
    {
        std::cout << "Failed to receive TLSData" << std::endl;
        response.clear();
        tlsClient.closeConnection();
        return -1;
    }
    // 解析login登录请求
    std::cout << std::string(response.begin(), response.end()) << std::endl;
    char *respStrChar_ = &response[0];
    if (!tlsClient.analyzeTLSpacket(respStrChar_))
    {
        std::cout << "controller refuse to login" << std::endl;
        response.clear();
        tlsClient.closeConnection();
        return -1;
    }
    cout << "controller accept login" << endl;

    // 发送请求服务
    if (!tlsClient.sendServiceRequest())
    {
        std::cout << "send service request failed" << std::endl;
        response.clear();
        tlsClient.closeConnection();
        return -1;
    }
    cout << "Serivce req sent" << endl;
    // 接收服务信息
    response.clear();
    if (!tlsClient.receiveTLSData(response))
    {
        std::cout << "Failed to receive TLSData" << std::endl;
        response.clear();
        tlsClient.closeConnection();
        return -1;
    }
    // 解析服务信息
    // std::cout << "receive service info: "<<std::string(response.begin(), response.end()) << std::endl;
    respStrChar_ = &response[0];
    if (!tlsClient.analyzeTLSpacket(respStrChar_))
    {
        std::cout << "analyse failed" << std::endl;
        response.clear();
        tlsClient.closeConnection();
        return -1;
    }
    cout << "parse serivceList success" << endl;
    cout << "respStrChar_ is: " << respStrChar_ << endl;
    // todo 检查为什么respStrChar_为什么最后多了几个字符
    cout << "last char of respStrChar_ is: " << respStrChar_[strlen(respStrChar_) - 1] << endl;

    vector<string> gatewayInfo = tlsClient.getParses();

    // 断开与controller的连接
    // 不需要断开，因为后续还需要上传数据
    // todo
    tlsClient.closeConnection();

    SPAProxyClient spaClient(gatewayInfo[0], atoi(gatewayInfo[1].c_str()));
    if (!spaClient.connectToSPAServer())
    {
        std::cerr << "Failed to connect to server." << std::endl;
        spaClient.closeConnection();
        return -1;
    }
    spaClient.initialSPA(gatewayInfo[2].c_str(), gatewayInfo[3].c_str());

    spaClient.sendSPAData();
    if (!spaClient.sendSPAData())
    {
        std::cerr << "Failed to send data." << std::endl;
        spaClient.closeConnection();
        return -1;
    }
    response.clear();
    if (!spaClient.receiveSPAData(response))
    {
        std::cout << "Failed to receive SPA response" << std::endl;
        response.clear();
        spaClient.closeConnection();
        return -1;
    }
    char *resp_ = &response[0];
    if (!spaClient.analyzeSPApacket(resp_))
    {
        std::cout << "Failed to analyze SPA response" << std::endl;
        response.clear();
        spaClient.closeConnection();
        return -1;
    }
    // 关闭与网关的SPA连接
    spaClient.closeConnection();
    // 与网关 tls 握手
    tlsClient.TLSsetter(gatewayInfo[0], atoi(gatewayInfo[1].c_str()));
    status = tlsClient.connectToTLSServer();
    if (!status)
    {
        std::cerr << "Failed to connect to server." << std::endl;
        return -1;
    }
    string hello_msg = "hello gateway!";
    vector<char> vec1;
    vec1.assign(hello_msg.begin(), hello_msg.end());
    if (!tlsClient.sendTLSData(vec1))
    {
        std::cout << "Failed to send TLS hello" << std::endl;
        vec1.clear();
        tlsClient.closeConnection();
        return -1;
    }
    tlsClient.closeConnection();
    return 0;
}