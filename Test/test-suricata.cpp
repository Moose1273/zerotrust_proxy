
#include "suricata/suricata/src/suricata.h"
#include <iostream>
#include <boost/asio.hpp>

using namespace boost::asio;
using ip::tcp;

int main(int argc, char* argv[]) {
  // 目标服务器的IP地址和端口号
  std::string target_ip = "127.0.0.1";
  unsigned short target_port = 80;

  // 创建io_service和TCP客户端
  io_service io_service;
  tcp::socket socket(io_service);
  tcp::resolver resolver(io_service);

  // 解析目标服务器的IP地址和端口号
  tcp::resolver::query query(target_ip, std::to_string(target_port));
  tcp::resolver::iterator iterator = resolver.resolve(query);

  // 连接目标服务器
  boost::asio::connect(socket, iterator);

  // 创建HTTP GET请求并发送到目标服务器
  std::string request = "GET / HTTP/1.1\r\nHost: " + target_ip + "\r\n\r\n";

  // 初始化Suricata引擎
  SuricataEngine se;
  int ret = suricata_init(&se, NULL);
  if (ret != SC_ERR_SUCCESS) {
    std::cerr << "Failed to initialize Suricata" << std::endl;
    return -1;
  }

  // 配置Suricata规则文件
  ret = suricata_load_rules(&se, "suricata.rules");
  if (ret != SC_ERR_SUCCESS) {
    std::cerr << "Failed to load Suricata rules" << std::endl;
    suricata_exit(&se);
    return -1;
  }

  // 进行流量过滤
  if (suricata_run(&se, request.c_str(), request.size()) == SC_TRUE) {
    std::cout << "Request passed the filter" << std::endl;

    // 发送请求到目标服务器
    boost::asio::write(socket, boost::asio::buffer(request));

    // 读取服务器响应并输出到控制台
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");
    std::cout << "Received response from server: " << &response << std::endl;
  } else {
    std::cout << "Request blocked by the filter" << std::endl;
  }

  // 关闭连接
  socket.close();

  // 释放Suricata资源
  suricata_exit(&se);

  return 0;
}
