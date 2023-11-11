#include "SPA_Proxy.h"

SPAProxyClient::SPAProxyClient(){
    
}

SPAProxyClient::SPAProxyClient(const std::string &serverAddr, int serverPort) : m_serverAddr(serverAddr), m_serverPort(serverPort)
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
SPAProxyClient::~SPAProxyClient()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

// connect to UDP server
int SPAProxyClient::connectToSPAServer()
{
    m_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket == INVALID_SOCKET)
    {
        return false;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(m_serverAddr.c_str());
    server.sin_port = htons(m_serverPort);

    if (connect(m_socket, (struct sockaddr *)&server, sizeof(server)) != 0)
    {
        return false;
    }

    return true;
}
int SPAProxyClient::initialSPA(std::string hotp, std::string hmac)
{
    std::string ip;
    /* Windows系统 */
#ifdef _WIN32
    // 执行ipconfig命令，并获取命令输出
    FILE* fp = _popen("ipconfig | findstr /i \"IPv4\"", "r");
    if (fp != nullptr) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            char* pos = strstr(buffer, "IPv4");
            if (pos != nullptr) {
                ip = pos + strlen("IPv4 Address. . . . . . . . . . . :");
                ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
                break;
            }
        }
        _pclose(fp);
    }

    // Linux系统
#else
    /* 执行ip命令，并获取命令输出 */
    FILE* fp = popen("ip addr | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d'/' -f1", "r");
    if (fp != nullptr) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            ip = buffer;
            ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
            break;
        }
        pclose(fp);
    }
#endif
    //std::cout<<ip<<endl;
	uint32_t iaddr = inet_addr(ip.c_str());
	uint32_t ipAddr = htonl(iaddr);
	spaInfo.ip_address = ipAddr;

	/* initial message_type */
	spaInfo.message_type = 0;

	/* initial default_value */
    spaInfo.default_value[0] = 0;
    spaInfo.default_value[1] = 0;
    //sdpid
    spaInfo.default_value[2] = 1145;
    std::string decode_hotp, decode_hmac;

    bool status = decode(hotp.c_str(), hotp.size(), &decode_hotp);
    if(!status){
        return SOCKET_ERROR;
    }
    status = decode(hmac.c_str(), hmac.size(), &decode_hmac);
    if(!status){
        return SOCKET_ERROR;
    }
    std::memcpy(spaInfo.HOTP, decode_hotp.data(), decode_hotp.length());
    std::memcpy(spaInfo.hmac, decode_hmac.data(), decode_hmac.length());
    // for (auto &b: spaInfo.HOTP) {
    //     std::cout << (int)(b) << ' ';
    // }
    // std::cout<<std::endl;
    // for (auto &b: spaInfo.hmac) {
    //     std::cout << (int)(b) << ' ';
    // } 
	return SOCKET_SUCCESS;
}


// initial and send SPA data packet
int SPAProxyClient::sendSPAData()
{
    cout<<"sizeof(spaInfo) is: "<<sizeof(spaInfo)<<endl;
    cout<<"ipaddress is: "<<spaInfo.ip_address<<" "<<sizeof(spaInfo.ip_address)<<endl;
    cout<<"timestamp is: "<<spaInfo.timestamp<<" "<<sizeof(spaInfo.timestamp)<<endl;
    cout<<"random_num is: "<<spaInfo.random_num<<" "<<sizeof(spaInfo.random_num)<<endl;
    cout<<"message_type is: "<<spaInfo.message_type<<" "<<sizeof(spaInfo.message_type)<<endl;
    cout<<"default_value is: "<<spaInfo.default_value[0]<<" "<<spaInfo.default_value[1]<<" "<<spaInfo.default_value[2]<<" "<<sizeof(spaInfo.default_value)<<endl;
    cout<<"userID is: "<<spaInfo.userID<<" "<<sizeof(spaInfo.userID)<<endl;
    cout<<"deviceID is: "<<spaInfo.deviceID<<" "<<sizeof(spaInfo.deviceID)<<endl;
    cout<<"HOTP is: "<<spaInfo.HOTP<<" "<<sizeof(spaInfo.HOTP)<<endl;
    cout<<"hmac is: "<<spaInfo.hmac<<" "<<sizeof(spaInfo.hmac)<<endl;
    //int result = 0;
    socklen_t serverLen = sizeof(server);
    int result = sendto(m_socket, (char *)&spaInfo, sizeof(spaInfo), 0, (sockaddr*)&server,  serverLen);
    if(result != sizeof(spaInfo)){
        return SOCKET_ERROR;
    }
    return SOCKET_SUCCESS;
}

int SPAProxyClient::receiveSPAData(std::vector<char> &data)
{
    // 设置超时时间为5秒
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    // 设置文件描述符集合
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(m_socket, &readfds);

    // 调用 select 函数，等待数据到达或超时发生
    int result = select(m_socket + 1, &readfds, NULL, NULL, &timeout);
    if (result == -1) {
        // select 出错
        printf("select function failed\n");
        return SOCKET_ERROR;
    } else if (result == 0) {
        // 超时发生，未收到数据
        printf("Timeout occurred, recv SPA response failed\n");
        return TIMEOUT_ERROR;
    }
    char buffer[1024];
    socklen_t serverLen = sizeof(server);
    int numBytes = recvfrom(m_socket, buffer, sizeof(buffer), 0, (sockaddr*)&server,  &serverLen);
    if (numBytes <= 0)
    {
        printf("Zero bytes received\n");
        return SOCKET_ERROR;
    }
    std::cout<<"len of buffer is: "<<strlen(buffer)<<endl;
    std::cout<<buffer<<endl;
    data.insert(data.end(), buffer, buffer + numBytes);
    return SOCKET_SUCCESS;
}

int SPAProxyClient::analyzeSPApacket(char* buffer){
    cJSON *root = cJSON_Parse(buffer);
    if (!root)
    {
        std::cerr << "Parse SPA packet failed!" << std::endl;
        cJSON_Delete(root);
        return 0;
    }
    cJSON *item = nullptr;
    char *action_str = nullptr;
    item = cJSON_GetObjectItem(root, "action");
    if (item != nullptr)
    {
        // 判断是不是字符串类型
        if (item->type == cJSON_String)
        {
            // 通过函数获取值
            action_str = cJSON_Print(item);
            cout << "this is action_str: " << action_str << endl;
            if (strcmp(action_str, "\"spa_response\"") == 0)
            {
                // 做处理
                char *status_str = nullptr;
                cJSON *idx = cJSON_GetObjectItem(root, "status");
                status_str = cJSON_Print(idx);
                cout << "this is status_str: " << status_str << endl;
                if (strcmp(status_str, "\"200\"") == 0)
                {
                    // todo:200之后要干什么
                    std::cout << "SPA packet accepted" << std::endl;
                    free(status_str);
                    free(action_str);
                    return SOCKET_SUCCESS;
                }
                else if (strcmp(status_str, "\"300\"") == 0)
                {
                    std::cout << "SPA packet rejected" << std::endl;
                    free(status_str);
                    free(action_str);
                    return 0;
                }
                else
                {
                    // todo 其他状态码
                    std::cout << "unrecognized status string" << std::endl;
                    free(status_str);
                    free(action_str);
                    return 0;
                }
            }
            else
            {
                /* code */
                // todo 其他action

                cout << "coming to else" << endl;
            }
        }
        else
        {
            cout << "not a cJSON_String type" << endl;
        }
        /* 通过函数返回的指针需要自行free，否则会导致内存泄漏 */
        free(action_str);
    }
    cJSON_Delete(root);
    return SOCKET_SUCCESS;
}

void SPAProxyClient::closeConnection()
{
#ifdef _WIN32
    closesocket(m_socket);
#else
    close(m_socket);
#endif
}

/* int main(){
    SPAProxyClient c1;
    string str1 = "Y74ql4I+vTtfOendVb45mUY8DlgYgJy/DWeiLkl98Qo=";
    c1.initialSPA(str1, str1);
    c1.sendSPAData();
} */