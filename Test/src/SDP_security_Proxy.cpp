#include "SDP_security_Proxy.h"
using namespace std;
//extern FILE* logFile;
int SDP_Proxy(FILE* logFile)
{
    fseek(logFile, 0, SEEK_END);
    if(logFile == nullptr || logFile == NULL){
        cout<<"logFile is a nullptr\n";
    }
    // 向controller发起SPA请求
    SPAProxyClient client("121.248.48.211", 8881);
    int status = 0;
    status = client.connectToSPAServer();
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to connect to server in SPA." << std::endl;
        INFO_LOG(logFile, "Failed to connect to sdp controller");
        return SOCKET_ERROR;
    }
    // cout<<status<<endl;
    // 构造请求
    status = client.initialSPA("", "");
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to initial SPA data." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to initial SPA", getCurrentTime().c_str());
        client.closeConnection();
        return SOCKET_ERROR;
    }
    status = client.sendSPAData();
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to send data." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to send SPA to controller", getCurrentTime().c_str());
        client.closeConnection();
        return SOCKET_ERROR;
    }
    // 收到SPA回复
    std::vector<char> response;
    status = client.receiveSPAData(response);
     
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "Failed to receive SPA response from controller" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to receive SPAData from controller", getCurrentTime().c_str());
        response.clear();
        client.closeConnection();
        return SOCKET_ERROR;
    }
    // print response data.
    // std::cout << std::string(response.begin(), response.end()) << std::endl;
    // std::cout << response.size() << endl;
    response.clear();
    client.closeConnection();

    // 向controller发起TLS请求
    TLSProxyClient tlsClient("121.248.48.211", 8889);
    status = tlsClient.connectToTLSServer();
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to connect to server in TLS." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to connect to server", getCurrentTime().c_str());
        return SOCKET_ERROR;
    }

    std::vector<char> req;
    status = tlsClient.constructLoginRequest(req);
    status = tlsClient.sendTLSData(req);
    if (status != SOCKET_SUCCESS)
    {
        cerr << "send TLS log_req failed" << endl;
        INFO_LOG(logFile, "时间：%s, Failed to send TLS log_req to controller", getCurrentTime().c_str());
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }

    // 接收login响应
    status = tlsClient.receiveTLSData(response);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "Failed to receive TLSData" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to receive login response from controller", getCurrentTime().c_str());
        response.clear();
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }
    // 解析login登录请求
    std::cout << std::string(response.begin(), response.end()) << std::endl;
    char *respStrChar_ = &response[4];
    status = tlsClient.analyzeTLSpacket(respStrChar_);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "analyzeTLSpacket failed" << std::endl;
        INFO_LOG(logFile, "时间：%s, Authtication failed, controller refuse to login", getCurrentTime().c_str());
        response.clear();
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }
    cout << "controller accept login" << endl;

    // 发送请求服务
    req.clear();
    status = tlsClient.constructServiceRequest(req);
    status = tlsClient.sendTLSData(req);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "send service request failed" << std::endl;
        INFO_LOG(logFile, "时间：%s, Send service request to controller failed", getCurrentTime().c_str());
        response.clear();
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }
    // 接收服务信息
    response.clear();
    status = tlsClient.receiveTLSData(response);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "Failed to receive TLSData" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to receive Service Data from controller", getCurrentTime().c_str());
        response.clear();
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }
    std::cout << "receive service info: "<<std::string(response.begin(), response.end()) << std::endl;
    // 解析服务信息
    respStrChar_ = &response[4];
    //cout << "respStrChar_ is: " << respStrChar_ << endl;
    // todo: 检查为什么respStrChar_为什么最后多了几个字符
    //cout << "last char of respStrChar_ is: " << respStrChar_[strlen(respStrChar_) - 1] << endl;
    status = tlsClient.analyzeTLSpacket(respStrChar_);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "analyse failed" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to analyse Service Data from controller", getCurrentTime().c_str());
        response.clear();
        tlsClient.closeConnection();
        return SOCKET_ERROR;
    }
    vector<string> gatewayInfo = tlsClient.getParses(); 

    // 断开与controller的连接
    // 不需要断开，因为后续还需要上传数据
    // todo:上传数据给controller
    //tlsClient.closeConnection();

    //SPAProxyClient spaClient(gatewayInfo[0], atoi(gatewayInfo[1].c_str()));
    SPAProxyClient spaClient("121.248.49.48", 9999);
    //int status;
    status = spaClient.connectToSPAServer();
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to connect to server." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to connect to gateway in SPA", getCurrentTime().c_str());
        spaClient.closeConnection();
        return SOCKET_ERROR;
    }
    /* 
    * gatewayInfo[2]:hotp
    * gatewayInfo[3]:hmac
    */
    spaClient.initialSPA(gatewayInfo[2], gatewayInfo[3]);

    //spaClient.initialSPA("Y74ql4I+vTtfOendVb45mUY8DlgYgJy/DWeiLkl98Qo=", "Y74ql4I+vTtfOendVb45mUY8DlgYgJy/DWeiLkl98Qo=");

    status = spaClient.sendSPAData();
    //std::vector<char> response;
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to send SPA." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to send SPA to gateway", getCurrentTime().c_str());
        spaClient.closeConnection();
        return SOCKET_ERROR;
    }
    response.clear();
    status = spaClient.receiveSPAData(response);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "Failed to receive SPA response" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to receive SPA response from gateway", getCurrentTime().c_str());
        response.clear();
        spaClient.closeConnection();
        return SOCKET_ERROR;
    }
    char *resp_ = &response[0];
    status = spaClient.analyzeSPApacket(resp_);
    if (status != SOCKET_SUCCESS)
    {
        std::cout << "Analyze SPA response failed" << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to Analyze SPA response from gateway", getCurrentTime().c_str());
        response.clear();
        spaClient.closeConnection();
        return SOCKET_ERROR;
    }
    /* 关闭与网关的SPA连接 */
    spaClient.closeConnection();
    /* 与网关 tls 握手 */
    //TLSProxyClient tlsClient;
    tlsClient.TLSsetter("121.248.49.48", 8888);
    status = tlsClient.connectToTLSServer();
    if (status != SOCKET_SUCCESS)
    {
        std::cerr << "Failed to connect to server." << std::endl;
        INFO_LOG(logFile, "时间：%s, Failed to connect gateway in TLS", getCurrentTime().c_str());
        return SOCKET_ERROR;
    }
    printf("TLS connection ready\n");

    /* 主动结束本次会话以发起下一次会话 */
    std::string state = "";
    while (state.compare("close") != 0)
    {
        printf("type \"close\" to close this connection\n");
        cin >> state;
    }
    
    tlsClient.closeConnection();
    return  SOCKET_SUCCESS;
}