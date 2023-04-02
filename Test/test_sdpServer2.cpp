#include <stdio.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "util.h"
#include "communication/cJSON.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#define IP_ADDRESS "121.248.51.84"
#define PORT 5656
#define BUF_SIZE 3000
#include "communication/SPA.h"
using namespace std;

void printSPA(SPA msg)
{
    std::cout << "The SPA packet content: " << std::endl;

    std::cout << "User ID: ";
    std::cout << msg.userID << " "<< std::endl;

    std::cout << "Device ID: ";
    std::cout << msg.deviceID << " "<<std::endl;

    std::cout << "Time Stamp: " << msg.timestamp << std::endl;
    std::cout << "Nonce: " << msg.random_num << std::endl;
    std::cout << "Source IP: " << msg.ip_address << std::endl;
    std::cout << "Destination message_type: " << msg.message_type << std::endl;

    std::cout << "HMAC: ";
    std::cout << msg.hmac << " "<< std::endl;

    std::cout << msg.HOTP << " "<< std::endl;

    std::cout << "Name: " << msg.name << std::endl;
    std::cout << "Type: " << msg.type << std::endl;
}

int main(int argc, char *argv[])
{
    // 加载数字证书和私钥
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "./keys/server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./keys/server.key", SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_load_verify_locations(ctx, "./keys/ca.crt", nullptr);

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
    // if (listen(sockfd, 5) < 0)
    // {
    //     cerr << "Error listening socket." << endl;
    //     return 1;
    // }
    while (1)
    {
        // normal udp test

        SPA test;
        socklen_t client_adr_sz = sizeof(clnt_addr);
        ssize_t str_len = recvfrom(sockfd, message, BUF_SIZE, 0,
                                   (struct sockaddr *)&clnt_addr, &client_adr_sz);

        struct SPA packet;
        errif(memcpy(&packet, message, sizeof(SPA)) == NULL, "Error copying data to SPA struct");
        std::cout << "received message from IP(" << inet_ntoa(clnt_addr.sin_addr) << "), PORT(" << clnt_addr.sin_port << "):" << std::endl;
        printSPA(packet);
        // 定义对象 { }
        cJSON *interest = cJSON_CreateObject();
        // 插入元素，对应 键值对
        cJSON_AddItemToObject(interest, "action", cJSON_CreateString("spa_response")); // 当值是字符串时，需要使用函数cJSON_CreateString()创建
        cJSON_AddItemToObject(interest, "status", cJSON_CreateString("200"));
        char *cPrint = cJSON_Print(interest);
        char newmessage[] = "this is a reply message!";
        cout<<"sent message: "<<cPrint<<endl<<"len message is: "<< strlen(cPrint)<<endl;
        //发送*cPrint在下面第三个参数需要使用strlen()，newmessage[]可以使用sizeof(),
        //sizeof是编译器确定的，strlen是运行时确定
        sendto(sockfd, cPrint, strlen(cPrint), 0,
               (struct sockaddr *)&clnt_addr, client_adr_sz);
        free(cPrint);
        cJSON_Delete(interest);

        // tls test
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
        // // 接收消息
        // char buffer[1024];
        // SSL_read(ssl, buffer, sizeof(buffer));
        // printf("Received message from server: %s\n", buffer);
        // // 定义对象 { }
        // cJSON *interest = cJSON_CreateObject();
        // // 插入元素，对应 键值对
        // cJSON_AddItemToObject(interest, "action", cJSON_CreateString("login_response")); // 当值是字符串时，需要使用函数cJSON_CreateString()创建
        // cJSON_AddItemToObject(interest, "status", cJSON_CreateString("200"));
        // char *cPrint = cJSON_Print(interest);
        // // string welcome_msg = "Welcome, client!";
        // SSL_write(ssl, cPrint, strlen(cPrint));
        // cout << "发送一个消息" << endl;
        // cout << cPrint << endl;
        // free(cPrint);
        // cJSON_Delete(interest);

        // // 收到service_req
        // memset(buffer, '\0', sizeof(buffer));
        // SSL_read(ssl, buffer, sizeof(buffer));
        // printf("Received message from server: %s\n", buffer);

        // // 发送服务
        // //  定义对象 { }
        // cJSON *root = cJSON_CreateObject();
        // cJSON_AddItemToObject(root, "action", cJSON_CreateString("service_response")); 
        // cJSON *service_data = cJSON_CreateObject();
        // cJSON_AddItemToObject(service_data, "hotp", cJSON_CreateString("this is a hotp"));
        // cJSON_AddItemToObject(service_data, "hmac", cJSON_CreateString("this is a hmac"));
        // cJSON_AddItemToObject(service_data, "updateTime", cJSON_CreateString("2023/03/31"));
        // cJSON_AddItemToObject(service_data, "expireTime", cJSON_CreateString("2023/03/32"));
        // // 定义 { } 对象
        // cJSON *serviceObject1 = cJSON_CreateObject();
        // cJSON_AddItemToObject(serviceObject1, "serverId", cJSON_CreateString("1"));
        // cJSON_AddItemToObject(serviceObject1, "serverDescription", cJSON_CreateString("this is the first serverDescription")); 
        // cJSON_AddItemToObject(serviceObject1, "gatewayId", cJSON_CreateString("this is the first gatewayId")); 
        // cJSON_AddItemToObject(serviceObject1, "gatewayIP", cJSON_CreateString("123.456.789.123")); 
        // cJSON_AddItemToObject(serviceObject1, "gatewayPort", cJSON_CreateString("1111")); 


        // cJSON *serviceObject2 = cJSON_CreateObject();
        // cJSON_AddItemToObject(serviceObject2, "serverId", cJSON_CreateString("2"));
        // cJSON_AddItemToObject(serviceObject2, "serverDescription", cJSON_CreateString("this is the second serverDescription")); 
        // cJSON_AddItemToObject(serviceObject2, "gatewayId", cJSON_CreateString("this is the second gatewayId")); 
        // cJSON_AddItemToObject(serviceObject2, "gatewayIP", cJSON_CreateString("321.654.987.321")); 
        // cJSON_AddItemToObject(serviceObject2, "gatewayPort", cJSON_CreateString("1111")); 

        // // 定义 [ ] 数组
        // cJSON *serviceList = cJSON_CreateArray();
        // // 往数组中添加元素
        // cJSON_AddItemToArray(serviceList, serviceObject1);
        // cJSON_AddItemToArray(serviceList, serviceObject2);

        // cJSON_AddItemToObject(service_data,"serviceList", serviceList);
        // cJSON_AddItemToObject(root,"data", service_data);


        // cPrint = cJSON_Print(root);
        // // string welcome_msg = "Welcome, client!";
        // SSL_write(ssl, cPrint, strlen(cPrint));
        // cout << "发送一个消息" << endl;
        // cout << cPrint << endl;


        // free(cPrint);
        // cJSON_Delete(root);
        // // 关闭 SSL 连接(no need)
        // // SSL_shutdown(ssl);
        // // SSL_free(ssl);
        // // close(cli_sockfd);
        // // X509_free(client_cert);
    }
    // 释放 SSL 上下文
    // SSL_CTX_free(ctx);

    close(sockfd);
    return 0;
}