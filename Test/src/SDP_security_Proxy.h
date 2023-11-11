#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include "util.h"
#include "logger.h"
#include "SPA_Proxy.h"
#include "TLS_Proxy.h"
typedef int SOCKET;
    /**
     * @brief SDP运行代理
     * @param logFile 日志文件句柄
     * @return !1-代理异常退出, 1-代理正常退出
     */
    int SDP_Proxy(FILE* logFile);