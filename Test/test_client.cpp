// #include <iostream>
// #include <string>
// #include <boost/asio.hpp>

// using boost::asio::ip::tcp;

// std::string modify_request(const std::string& request)
// {
//     // 在这里实现你的拦截和修改逻辑
//     std::string modified_request = request;
//     // 这里简单地将请求体中的所有小写字母转换为大写字母
//     std::transform(modified_request.begin(), modified_request.end(), modified_request.begin(), ::toupper);
//     return modified_request;
// }

// void handle_client_request(tcp::socket& client_socket, tcp::socket& server_socket)
// {
//     try
//     {
//         // 接收客户端请求并转发到目标服务器
//         boost::asio::streambuf request_buffer;
//         boost::asio::read_until(client_socket, request_buffer, "\r\n\r\n");
//         std::string request_data(boost::asio::buffers_begin(request_buffer.data()), boost::asio::buffers_end(request_buffer.data()));

//         std::string modified_request = modify_request(request_data);
//         boost::asio::write(server_socket, boost::asio::buffer(modified_request));

//         // 接收目标服务器响应并返回给客户端
//         boost::asio::streambuf response_buffer;
//         boost::system::error_code error;
//         while (boost::asio::read(server_socket, response_buffer, boost::asio::transfer_at_least(1), error))
//         {
//             boost::asio::write(client_socket, response_buffer);
//             response_buffer.consume(response_buffer.size());
//         }
//     }
//     catch (std::exception& e)
//     {
//         std::cerr << "Exception: " << e.what() << std::endl;
//     }
// }

// int main(int argc, char* argv[])
// {
//     if (argc != 4)
//     {
//         std::cerr << "Usage: proxy_client <listen_port> <target_host> <target_port>" << std::endl;
//         return 1;
//     }

//     try
//     {
//         // 初始化io_context对象
//         boost::asio::io_context io_context;

//         // 创建本地监听端点
//         tcp::endpoint local_endpoint(tcp::v4(), std::atoi(argv[1]));

//         // 创建本地监听套接字
//         tcp::acceptor acceptor(io_context, local_endpoint);

//         // 连接目标服务器
//         tcp::resolver resolver(io_context);
//         tcp::resolver::results_type endpoints = resolver.resolve(argv[2], argv[3]);
//         tcp::socket server_socket(io_context);
//         boost::asio::connect(server_socket, endpoints);

//         while (true)
//         {
//             // 等待客户端
//             tcp::socket client_socket(io_context);
//             acceptor.accept(client_socket);

//             // 处理客户端请求
//             std::thread(handle_client_request, std::ref(client_socket), std::ref(server_socket)).detach();
//         }
//     }
//     catch (std::exception& e)
//     {
//         std::cerr << "Exception: " << e.what() << std::endl;
//     }

//     return 0;
// }
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>

using namespace std;

int main()
{
    // 加载数字证书和私钥
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr);

    // 创建套接字
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        cerr << "Error creating socket." << endl;
        return 1;
    }

    // 连接服务器
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7878);
    addr.sin_addr.s_addr = inet_addr("121.248.51.84");
    if (connect(sockfd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        cerr << "Error connecting to server." << endl;
        return 1;
    }

    // 创建 SSL 连接
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // SSL 握手
    if (SSL_connect(ssl) <= 0)
    {
        cerr << "SSL handshake failed." << endl;
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    // 获取服务器证书信息
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert == nullptr)
    {
        cerr << "No server certificate provided." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    // 验证服务器证书
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK)
    {
        cerr << "Server certificate verification failed: " << X509_verify_cert_error_string(verify_result) << endl;
        X509_free(server_cert);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        return 1;
    }

    // 获取服务器证书主题信息
    // X509_NAME *subject_name = X509_get_subject_name(server_cert);
    // int nid = OBJ_txt2nid("CN");
    // X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject_name, X509_NAME_get_index_by_NID(subject_name, nid, -1));
    // ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
    // char *server_name = reinterpret_cast<char *>(data);

    // 输出服务器证书信息
    // cout << "Server certificate provided:" << endl;
    // cout << "Subject: " << data << endl;

    // 发送客户端证书
    SSL_write(ssl, "Hello, server!", 14);
    cout<<"已发送证书"<<endl;
    // 接收欢迎消息
    char buf[1024];
    SSL_read(ssl, buf, 1024);
    cout << "Received message: " << buf;

    // 关闭 SSL 连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    X509_free(server_cert);
    SSL_CTX_free(ctx);

    return 0;
}