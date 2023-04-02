#include "TLS_Proxy.h"

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
bool TLSProxyClient::connectToTLSServer()
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
        return false;
    }
    SSL_set_fd(m_ssl, m_socket);

    // SSL 握手
    if (SSL_connect(m_ssl) <= 0)
    {
        cerr << "SSL handshake failed." << endl;
        SSL_free(m_ssl);
        close(m_socket);
        return 1;
    }

    // 获取服务器证书信息
    server_cert = SSL_get_peer_certificate(m_ssl);
    if (server_cert == nullptr)
    {
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
    // SSL_write(m_ssl, "Hello, server!", 14);
    return true;
}

bool TLSProxyClient::sendTLSData(const std::vector<char> &data)
{
    int result = SSL_write(m_ssl, data.data(), data.size());
    return result > 0;
}

bool TLSProxyClient::receiveTLSData(std::vector<char> &data)
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

bool TLSProxyClient::analyzeTLSpacket(char *buffer)
{
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
                    std::cout << "controller accept connection" << std::endl;
                }
                else if (strcmp(status_str, "\"300\"") == 0)
                {
                    std::cout << "controller refuse connection" << std::endl;
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
            else if (strcmp(action_str, "\"login_response\"") == 0)
            {
                // 做处理
                char *status_str = nullptr;
                cJSON *idx = cJSON_GetObjectItem(root, "status");
                status_str = cJSON_Print(idx);
                cout << "this is status_str: " << status_str << endl;
                if (strcmp(status_str, "\"200\"") == 0)
                {
                    // todo:200之后要干什么
                    std::cout << "controller accept login" << std::endl;
                }
                else if (strcmp(status_str, "\"300\"") == 0)
                {
                    std::cout << "controller refuse login" << std::endl;
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
                    return 0;
                }
                // 获取数组长度
                auto len = cJSON_GetArraySize(service_list_idx);
                vector<pair<string, int>> serverIDS;
                unordered_set<string> serverIdMap;
                for (auto i = 0; i < len; ++i) // 对每个数组元素进行处理
                {
                    cJSON *obj = cJSON_GetArrayItem(service_list_idx, i); // 获取的数组里的obj
                    cJSON *serverId = NULL;
                    cJSON *val = NULL;
                    if (obj != NULL && obj->type == cJSON_Object)
                    {                                                    // 判断数字内的元素是不是obj类型
                        serverId = cJSON_GetObjectItem(obj, "serverId"); // 获得obj里的值

                        if (serverId != NULL && serverId->type == cJSON_String)
                        {
                            status_str = serverId->valuestring;
                            // printf("serverId = %s\n", status_str);
                            cout << "serverId = " << status_str << endl;
                            serverIdMap.insert(status_str);
                            serverIDS.push_back({status_str, i});
                        }
                        else
                        {
                            cerr << "get serverId failed!" << endl;
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
                        break;
                    }
                    // find service
                    else if (serverIdMap.find(serv) != serverIdMap.end())
                    {
                        char *gatewayIP = nullptr;
                        char *gatewayPort = nullptr;
                        char *hotp = nullptr;
                        char *hmac = nullptr;
                        // do something
                        cout << "do something" << endl;
                        int idx = -1;
                        for (auto iter : serverIDS)
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
                                        return -1;
                                    }
                                    cout << gatewayIP << " " << gatewayPort << " " << atoi(gatewayPort) << " " << hotp << " " << hmac << endl;
                                    setParses(gatewayIP, gatewayPort, hotp, hmac);
                                    // 怎么传回呢？
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
//发送登录请求
int TLSProxyClient::constructLoginRequest(std::vector<char> &data)
{
    char buffer[1024];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "action", cJSON_CreateString("login_request"));
    // 定义user data对象 { }
    cJSON *user_data = cJSON_CreateObject();
    cJSON_AddItemToObject(user_data, "userId", cJSON_CreateString("hb user"));
    cJSON_AddItemToObject(user_data, "password", cJSON_CreateNumber(123457896453));
    cJSON_AddItemToObject(root, "data", user_data);
    char *cPrint = cJSON_Print(root);
    memmove(buffer, cPrint, 1024);
    cout << buffer << endl;
    data.insert(data.end(), buffer, buffer + strlen(buffer));
    return true;
}

int TLSProxyClient::sendServiceRequest()
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "action", cJSON_CreateString("service_request"));
    char *ser_req = cJSON_Print(root);
    int result = SSL_write(m_ssl, ser_req, strlen(ser_req));
    return result > 0;
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
