#include "TLS_Proxy.h"
TLSProxyClient::TLSProxyClient(){
    #ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
    }
#endif
}
TLSProxyClient::TLSProxyClient(const std::string &serverAddr, int serverPort) : m_serverAddr(serverAddr), m_serverPort(serverPort)
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

TLSProxyClient::~TLSProxyClient()
{
    SSL_CTX_free(m_sslContext);
    EVP_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
}


void TLSProxyClient::TLSsetter(const std::string &serverAddr, int serverPort)
{
    m_serverAddr = serverAddr;
    m_serverPort = serverPort;
}

// connect to TLS server
int TLSProxyClient::connectToTLSServer()
{
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket == INVALID_SOCKET)
    {
        return false;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(m_serverAddr.c_str());
    server.sin_port = htons(m_serverPort);

    if (connect(m_socket, (struct sockaddr *)&server, sizeof(server)) != 0)
    {
        return SOCKET_ERROR;
    }
    // 初始化 OpenSSL 库并创建 SSL 上下文
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    // 加载数字证书和私钥
    m_sslContext = SSL_CTX_new(TLS_client_method());
    // 设置信任根证书
    errif(SSL_CTX_load_verify_locations(m_sslContext, CA_CRT_PATH, NULL) <= 0, "CA Cert load error");
    // 设置客户端证书，用来发给服务器进行双向验证
    errif(SSL_CTX_use_certificate_file(m_sslContext, CLIENT_CRT_PATH, SSL_FILETYPE_PEM) <= 0, "Client Cert load error");
    // 设置客户端私钥
    errif(SSL_CTX_use_PrivateKey_file(m_sslContext, CLIENT_KEY_PATH, SSL_FILETYPE_PEM) <= 0, "Client Key load error");
    // 检查私钥是否正确
    errif(!SSL_CTX_check_private_key(m_sslContext), "Client Key parse error");
    if (m_sslContext == nullptr)
    {
        return false;
    }
    m_ssl = SSL_new(m_sslContext);
    if (m_ssl == nullptr)
    {
        return SOCKET_ERROR;
    }
    SSL_set_fd(m_ssl, m_socket);

    // SSL 握手
    if (SSL_connect(m_ssl) <= 0)
    {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        close(m_socket);
        return SOCKET_ERROR;
    }

    // 获取服务器证书信息
    server_cert = SSL_get_peer_certificate(m_ssl);
    if (server_cert == nullptr)
    {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        close(m_socket);
        return SOCKET_ERROR;
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
        return SOCKET_ERROR;
    }
    // 发送客户端证书
    // SSL_write(m_ssl, "Hello, server!", 14);
    return SOCKET_SUCCESS;
}

int TLSProxyClient::sendTLSData(std::vector<char> &data)
{
    // 先发送数据大小
    size_t dataSize = data.size();
    int dataSize_int = data.size();
    cout<<dataSize_int<<endl;
    vector<char> length(4);
    length[0] = (dataSize_int >> 24) & 0xFF;
    length[1] = (dataSize_int >> 16) & 0xFF;
    length[2] = (dataSize_int >> 8) & 0xFF;
    length[3] = dataSize_int & 0xFF;
    
    int result = SSL_write(m_ssl, length.data(), length.size());
    // reverse(data.begin(), data.end());
    // // 将数据大小的每个字节（四字节）依次插入到数组开头
    // data.push_back((dataSize >> 24) & 0xFF);
    // data.push_back((dataSize >> 16) & 0xFF);
    // data.push_back((dataSize >> 8) & 0xFF);
    // data.push_back(dataSize & 0xFF);
    // cout<<&data[0]<<endl;
    // reverse(data.begin(), data.end());
    result = SSL_write(m_ssl, data.data(), data.size());
    if(result <= 0){
        return SOCKET_ERROR;
    }
    return SOCKET_SUCCESS;
}

int TLSProxyClient::sendData( std::vector<char> &data)
{
    int result = send(m_socket, data.data(), data.size(),0);
    return result > 0;
}

int TLSProxyClient::receiveTLSData(std::vector<char> &data)
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
        printf("Timeout occurred, recv TLS response failed\n");
        return TIMEOUT_ERROR;
    }
    char buffer[1024];
    int numBytes = SSL_read(m_ssl, buffer, sizeof(buffer));
    errif(numBytes <= 0, "none reply from server error");
    data.insert(data.end(), buffer, buffer + numBytes);
    return SOCKET_SUCCESS;
}

int TLSProxyClient::receiveData(std::vector<char> &data)
{
    char buffer[1024];
    int numBytes = recv(m_socket, buffer, sizeof(buffer), 0);
    errif(numBytes <= 0, "empty reply from server error");
    data.insert(data.end(), buffer, buffer + numBytes);
    return SOCKET_SUCCESS;
}

int TLSProxyClient::analyzeTLSpacket(char *buffer)
{
    cJSON *root = cJSON_Parse(buffer);
    if (!root)
    {
        std::cerr << "Parse packet failed!" << std::endl;
        cJSON_Delete(root);
        return SOCKET_ERROR;
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
            //cout << "this is action_str: " << action_str << endl;
            if (strcmp(action_str, "\"login_response\"") == 0)
            {
                // 做处理
                char *status_str = nullptr;
                cJSON *idx = cJSON_GetObjectItem(root, "status");
                status_str = cJSON_Print(idx);
                cout << "status_str is : " << status_str << endl;
                if (strcmp(status_str, "\"200\"") == 0)
                {
                    // todo:200之后要干什么
                    std::cout << "controller accept login" << std::endl;
                    free(status_str);
                    free(action_str);
                    return SOCKET_SUCCESS;
                }
                else if (strcmp(status_str, "\"300\"") == 0)
                {
                    std::cout << "controller refuse login" << std::endl;
                    free(status_str);
                    free(action_str);
                    return SOCKET_ERROR;
                }
                else
                {
                    // todo 其他状态码
                    free(status_str);
                    free(action_str);
                    return SOCKET_ERROR;
                }
            }
            // 服务请求响应
            // 从响应包中提取信息，构造SPA包发送给网关
            else if (strcmp(action_str, "\"service_response\"") == 0)
            {
                // 做处理
                char *status_str = nullptr;
                cJSON *data_idx = cJSON_GetObjectItem(root, "data");
                cJSON *service_list_idx = cJSON_GetObjectItem(data_idx, "serviceList");
                if (!service_list_idx)
                {
                    printf("Get service_list_idx error -1");
                    return SOCKET_ERROR;
                }
                // 获取数组长度
                auto len = cJSON_GetArraySize(service_list_idx);
                //service和对应ID
                vector<pair<string, int>> serviceIDS;
                //service池
                unordered_set<string> serviceIdMap;
                for (auto i = 0; i < len; ++i) // 对每个数组元素进行处理
                {
                    cJSON *obj = cJSON_GetArrayItem(service_list_idx, i); // 获取的数组里的obj
                    cJSON *serviceId = NULL;
                    cJSON *val = NULL;
                    if (obj != NULL && obj->type == cJSON_Object)
                    {                                                    // 判断数字内的元素是不是obj类型
                        serviceId = cJSON_GetObjectItem(obj, "serviceId"); // 获得obj里的值

                        if (serviceId != NULL && serviceId->type == cJSON_String)
                        {
                            status_str = serviceId->valuestring;
                            //cout << "serverId = " << status_str << endl;
                            serviceIdMap.insert(status_str);
                            serviceIDS.push_back({status_str, i});
                        }
                        else
                        {
                            cerr << "get seviceId failed!" << endl;
                            return SOCKET_ERROR;
                        }
                    }
                }
                // user select a service
                cout << "plz select a serviceId or q for quit" << endl;
                string serv;
                while (1)
                {
                    cin >> serv;
                    if (serv.compare("q") == 0)
                    {
                        free(action_str);
                        cJSON_Delete(root);
                        return SOCKET_PENDING;
                    }
                    // find service
                    else if (serviceIdMap.find(serv) != serviceIdMap.end())
                    {
                        char *gatewayIP = nullptr;
                        char *gatewayPort = nullptr;
                        char *hotp = nullptr;
                        char *hmac = nullptr;
                        // do something
                        //cout << "do something" << endl;
                        int idx = -1;
                        for (auto iter : serviceIDS)
                        {
                            if (iter.first == serv)
                            {
                                cJSON *obj = cJSON_GetArrayItem(service_list_idx, iter.second);
                                if (obj != nullptr && obj->type == cJSON_Object)
                                {
                                    cJSON *IP = cJSON_GetObjectItem(obj, "gatewayIP");
                                    cJSON *PORT = cJSON_GetObjectItem(obj, "gatewayPort");
                                    cJSON *HOTP = cJSON_GetObjectItem(data_idx, "hotp");
                                    cJSON *HMAC = cJSON_GetObjectItem(data_idx, "hmac");
                                    char *gatewayIP = IP->valuestring;
                                    char *gatewayPort = PORT->valuestring;
                                    char *hotp = HOTP->valuestring;
                                    char *hmac = HMAC->valuestring;
                                    if(!gatewayIP || !gatewayPort || !hotp || !hmac)
                                    {
                                        cout<<"get gateway info failed!"<<endl;
                                        free(action_str);
                                        cJSON_Delete(root);
                                        return SOCKET_ERROR;
                                    }
                                    cout << gatewayIP << " " << gatewayPort << " " << atoi(gatewayPort) << " " << hotp << " " << hmac << endl;
                                    setParses(gatewayIP, gatewayPort, hotp, hmac);
                                }
                            }
                        }
                        break;
                    }
                    cout << "plz input a serviceId or type q for quit" << endl;
                }
            }
            else
            {
                /* code */
                // todo 其他action

                cout << "other anctions" << endl;
            }
        }
        else
        {
            cout << "not a cJSON_String type" << endl;
            cJSON_Delete(root);
            free(action_str);
            return SOCKET_ERROR;
        }
        // 通过函数返回的指针需要自行free，否则会导致内存泄漏
        free(action_str);
    }
    cJSON_Delete(root);
    return SOCKET_SUCCESS;
}
//发送登录请求
int TLSProxyClient::constructLoginRequest(std::vector<char> &data)
{
    char buffer[1024];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "action", cJSON_CreateString("login_request"));
    // 定义user data对象 { }
    cJSON *user_data = cJSON_CreateObject();
    cJSON_AddItemToObject(user_data, "username", cJSON_CreateString("HB_Client"));
    cJSON_AddItemToObject(user_data, "password", cJSON_CreateString("root"));
    cJSON_AddItemToObject(root, "data", user_data);
    char *cPrint = cJSON_Print(root);
    memmove(buffer, cPrint, 1024);
    std::cout << buffer << std::endl;
    data.insert(data.end(), buffer, buffer + strlen(buffer));
    return true;
}

int TLSProxyClient::constructServiceRequest(std::vector<char> &data)
{
    char buffer[1024];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "action", cJSON_CreateString("service_request"));
    char *ser_req = cJSON_Print(root);
    memmove(buffer, ser_req, 1024);
    std::cout << buffer << std::endl;
    data.insert(data.end(), buffer, buffer + strlen(buffer));
    return true;
}

void TLSProxyClient::setParses(char* gatewayIP, char* gatewayPort, char* hotp, char* hmac)
{
    parses.push_back(gatewayIP);
    parses.push_back(gatewayPort);
    parses.push_back(hotp);
    parses.push_back(hmac);
}

vector<string> TLSProxyClient::getParses()
{
    return parses;
}

void TLSProxyClient::closeConnection()
{
    SSL_shutdown(m_ssl);
    X509_free(server_cert);
    // SSL_free(m_ssl);
#ifdef _WIN32
    closesocket(m_socket);
#else
    close(m_socket);
#endif
}
