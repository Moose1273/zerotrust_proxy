#include "SPA_Proxy.h"

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
bool SPAProxyClient::connectToSPAServer()
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
int SPAProxyClient::initialSPA(const char* hotp, const char* hmac)
{

    std::string ip;

    // Windows系统
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
    // 执行ip命令，并获取命令输出
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

	uint32_t iaddr = inet_addr(ip.c_str());
	uint32_t ipAddr = htonl(iaddr);
	spaInfo.ip_address = ipAddr;

	// initial message_type
	spaInfo.message_type = 0;

	// initial default_value
    spaInfo.default_value[0] = 0;
    spaInfo.default_value[1] = 0;
    spaInfo.default_value[2] = 0;

	// initial HOTP
    if(hotp)
    {
        for(int i = 0; i < spaInfo.HOTP.size(); i++){
            if (hotp[i] == '1') {
            spaInfo.HOTP.set(strlen(hotp) - 1 - i); // 将第i位设置为1
            }
        }
    }

	// initial hmac
    if(hmac)
    {
        for(int i = 0; i < spaInfo.hmac.size(); i++){
            if (hmac[i] == '1') {
            spaInfo.hmac.set(strlen(hmac) - 1 - i); // 将第i位设置为1
            }
        }
    }
	return true;
}


// initial and send SPA data packet
bool SPAProxyClient::sendSPAData()
{
    cout<<"sizeof(spaInfo) is: "<<sizeof(spaInfo)<<endl;
    cout<<"ipaddress is: "<<spaInfo.ip_address<<" "<<sizeof(spaInfo.ip_address)<<endl;
    cout<<"timestamp is: "<<spaInfo.timestamp<<" "<<sizeof(spaInfo.timestamp)<<endl;
    cout<<"random_num is: "<<spaInfo.random_num<<" "<<sizeof(spaInfo.random_num)<<endl;
    cout<<"message_type is: "<<spaInfo.message_type<<" "<<sizeof(spaInfo.message_type)<<endl;
    cout<<"default_value is: "<<spaInfo.default_value[0]<<" "<<sizeof(spaInfo.default_value)<<endl;
    cout<<"userID is: "<<spaInfo.userID<<" "<<sizeof(spaInfo.userID)<<endl;
    cout<<"deviceID is: "<<spaInfo.deviceID<<" "<<sizeof(spaInfo.deviceID)<<endl;
    cout<<"HOTP is: "<<spaInfo.HOTP<<" "<<sizeof(spaInfo.HOTP)<<endl;
    cout<<"hmac is: "<<spaInfo.hmac<<" "<<sizeof(spaInfo.hmac)<<endl;
    int result = send(m_socket, (char *)&spaInfo, sizeof(spaInfo), 0);
    return result != SOCKET_ERROR;
}

bool SPAProxyClient::receiveSPAData(std::vector<char> &data)
{
    char buffer[1024];
    int numBytes = recv(m_socket, buffer, sizeof(buffer), 0);
    if (numBytes == SOCKET_ERROR || numBytes == 0)
    {
        return false;
    }
    cout<<"len of buffer is: "<<strlen(buffer)<<endl;
    cout<<buffer<<endl;
    data.insert(data.end(), buffer, buffer + numBytes);
    //std::cout << string(data.begin(), data.end()) << endl;
    bool status = analyzeSPApacket(buffer);
    if(!status){
        std::cerr<<"analyze SPA packet failed!"<<std::endl;
        return false;
    }
    return true;
}

bool SPAProxyClient::analyzeSPApacket(char* buffer){
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
                    free(status_str);
                    free(action_str);
                    return 0;
                }
                free(status_str);
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
        // 通过函数返回的指针需要自行free，否则会导致内存泄漏
        free(action_str);
    }
    cJSON_Delete(root);
    return 1;
}

void SPAProxyClient::closeConnection()
{
#ifdef _WIN32
    closesocket(m_socket);
#else
    close(m_socket);
#endif
}
