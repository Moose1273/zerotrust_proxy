#include <stdio.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#define IP_ADDRESS "121.248.51.84"
#define PORT 7878
#define BUF_SIZE 3000
#include "SPA.h"
using namespace std;

void printSPA(SPA msg) {
    std::cout << "The SPA packet content: " << std::endl;
    
    std::cout << "User ID: ";
    for (int i = 0; i < 4; i++) {
        std::cout << msg.userID.bits[i] << " ";
    }
    std::cout << std::endl;
    
    std::cout << "Device ID: ";
    for (int i = 0; i < 4; i++) {
        std::cout << msg.deviceID.bits[i] << " ";
    }
    std::cout << std::endl;
    
    std::cout << "Time Stamp: " << msg.timeStamp << std::endl;
    std::cout << "Nonce: " << msg.nonce << std::endl;
    std::cout << "Source IP: " << msg.sourceIP << std::endl;
    std::cout << "Destination Port: " << msg.destPort << std::endl;
    
    std::cout << "HMAC: ";
    for (int i = 0; i < 2; i++) {
        std::cout << msg.HMAC.bits[i] << " ";
    }
    std::cout << std::endl;

    std::cout << "Name: " << msg.name << std::endl;
    std::cout << "Type: " << msg.type << std::endl;
}

int main(int argc, char *argv[])
{
    // 加载数字证书和私钥
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr);

    char message[BUF_SIZE];
    // TSLserver:SOCK_STREAM, UDPserver:SOCK_DGRAM
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    errif(sockfd == -1, "socket create error");

    struct sockaddr_in serv_addr, clnt_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    serv_addr.sin_port = htons(PORT);

    errif(bind(sockfd, (sockaddr *)&serv_addr, sizeof(serv_addr)) == -1, "socket bind error");

    socklen_t clnt_addr_len = sizeof(clnt_addr);
    memset(&clnt_addr, 0, sizeof(clnt_addr));
    // 监听套接字 for tls
    // if (listen(sockfd, 5) < 0) {
    //     cerr << "Error listening socket." << endl;
    //     return 1;
    // }
    while (1)
    {
        //normal udp test
        // socklen_t client_adr_sz =  sizeof(clnt_addr);
        // ssize_t str_len = recvfrom(sockfd, message, BUF_SIZE, 0,
        //                         (struct sockaddr*)&clnt_addr, &client_adr_sz);

        // std::cout << "received message from IP(" << inet_ntoa(clnt_addr.sin_addr) << "), PORT(" << clnt_addr.sin_port << "):" << std::endl;
        // std::cout << "message: " << message << std::endl;
        // sendto(sockfd, message, str_len, 0,
        //                         (struct sockaddr*)&clnt_addr, client_adr_sz);


        //spa test
        socklen_t client_adr_sz =  sizeof(clnt_addr);
        ssize_t str_len = recvfrom(sockfd, message, BUF_SIZE, 0, 
                                (struct sockaddr*)&clnt_addr, &client_adr_sz);
        
        struct SPA packet;
        errif(memcpy(&packet, message, sizeof(SPA)) == NULL, "Error copying data to SPA struct");
        std::cout << "received message from IP(" << inet_ntoa(clnt_addr.sin_addr) << "), PORT(" << clnt_addr.sin_port << "):" << std::endl;
        printSPA(packet);
        char newmessage[] = "this is a reply message!";
        sendto(sockfd, newmessage, sizeof(newmessage), 0,
                                (struct sockaddr*)&clnt_addr, client_adr_sz);

        //tls test
        // socklen_t clnt_addr_len = sizeof(clnt_addr);
        // memset(&clnt_addr, 0, sizeof(clnt_addr));
        // int cli_sockfd = accept(sockfd, (sockaddr *)&clnt_addr, &clnt_addr_len);
        // if (cli_sockfd < 0)
        // {
        //     cerr << "Error accepting client." << endl;
        //     continue;
        // }
        // cout << "Accepted connection from " << inet_ntoa(clnt_addr.sin_addr) << ":" << ntohs(clnt_addr.sin_port) << endl;
        // // 创建 SSL 连接
        // SSL *ssl = SSL_new(ctx);
        // SSL_set_fd(ssl, cli_sockfd);

        // // SSL 握手
        // if (SSL_accept(ssl) <= 0)
        // {
        //     cerr << "SSL handshake failed." << endl;
        //     SSL_free(ssl);
        //     close(cli_sockfd);
        //     continue;
        // }

        // // 获取客户端证书信息
        // // X从SSL套接字中获取证书信息
        // X509 *client_cert = SSL_get_peer_certificate(ssl);
        // if (client_cert == nullptr)
        // {
        //     cerr << "No client certificate provided." << endl;
        //     SSL_shutdown(ssl);
        //     SSL_free(ssl);
        //     close(cli_sockfd);
        //     continue;
        // }
        // // 验证客户端证书
        // long verify_result = SSL_get_verify_result(ssl);
        // if (verify_result != X509_V_OK)
        // {
        //     cerr << "Client certificate verification failed: " << X509_verify_cert_error_string(verify_result) << endl;
        //     X509_free(client_cert);
        //     SSL_shutdown(ssl);
        //     SSL_free(ssl);
        //     close(cli_sockfd);
        // }


        // // 发送欢迎消息
        // string welcome_msg = "Welcome, client!";
        // SSL_write(ssl, welcome_msg.c_str(), welcome_msg.length());
        // cout<<"发送一个消息"<<endl;
        // cout<<welcome_msg.length()<<endl;

        // // 关闭 SSL 连接(no need)
        // // SSL_shutdown(ssl);
        // // SSL_free(ssl);
        // // close(cli_sockfd);
        // // X509_free(client_cert);
    }
    // 释放 SSL 上下文
    //SSL_CTX_free(ctx);

    close(sockfd);
    return 0;
}