#include <stdio.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "util.h"

#define IP_ADDRESS "121.248.51.84"
#define PORT 8888
#define BUF_SIZE 3000

int main(int argc, char *argv[]) {
    char message[BUF_SIZE];

    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    errif(sockfd == -1, "socket create error");

    struct sockaddr_in serv_addr, clnt_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    serv_addr.sin_port = htons(PORT);

    errif(bind(sockfd, (sockaddr*)&serv_addr, sizeof(serv_addr)) == -1, "socket bind error");
    
    socklen_t clnt_addr_len = sizeof(clnt_addr);
    memset(&clnt_addr, 0, sizeof(clnt_addr));

    while (1) {
        socklen_t client_adr_sz =  sizeof(clnt_addr);
        ssize_t str_len = recvfrom(sockfd, message, BUF_SIZE, 0, 
                                (struct sockaddr*)&clnt_addr, &client_adr_sz);
        
        std::cout << "received message from IP(" << inet_ntoa(clnt_addr.sin_addr) << "), PORT(" << clnt_addr.sin_port << "):" << std::endl;
        std::cout << "message: " << message << std::endl;
        sendto(sockfd, message, str_len, 0,
                                (struct sockaddr*)&clnt_addr, client_adr_sz);
    }
    close(sockfd);
    return 0;
}