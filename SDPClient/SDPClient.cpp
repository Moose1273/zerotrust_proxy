//#include "SPA2controller.cpp"
#include "SPA.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
using namespace std;
#pragma once

#define SERVER_IP "121.248.51.84"
#define PORT 8888

//获得当前设备IP地址
uint32_t getSourceIP() {
	std::string cmdLine(R"("curl checkip.amazonaws.com --no-progress-meter")");
	char buffer[1024] = { '\0' };
	FILE* pf = NULL;
	pf = popen(cmdLine.c_str(), "r");
	if (NULL == pf) {
		printf("open pipe failed\n");
		return -1;
	}
	std::string ret;
	while (fgets(buffer, sizeof(buffer), pf)) {
		ret += buffer;
	}
	pclose(pf);
	ret.pop_back();
	//cout << ret << endl;
	uint32_t iaddr = inet_addr(ret.c_str());
	uint32_t ans = htonl(iaddr);
	//std::cout << std::hex << ans << std::dec << std::endl;
	return ans;
}
int initialSPA(struct SPA* spa)
{
	spa->userID.bits[0] = 1234123412341234;
	spa->userID.bits[1] = 1234123412341234;
	spa->userID.bits[2] = 1234123412341234;
	spa->userID.bits[3] = 1234123412341234;
	spa->deviceID.bits[0] = 5678567856785678;
	spa->deviceID.bits[1] = 5678567856785678;
	spa->deviceID.bits[2] = 5678567856785678;
	spa->deviceID.bits[3] = 5678567856785678;
	spa->timeStamp = time(NULL);
	std::default_random_engine e;
	spa->nonce = e();
	spa->sourceIP = getSourceIP();
	spa->destPort = 8000;
	string name = "redis";
	strncpy(spa->name, name.c_str(), strlen(name.c_str())+1);
	string type = "HTTPS";
	strncpy(spa->type, type.c_str(), strlen(type.c_str()) + 1);
	return true;
}
int SPA2controller(SPA &spa)
{
	SOCKET m_Socket;
	SOCKADDR_IN m_RemoteAddress; //远程地址
	int m_RemoteAddressLen;

	// socket环境
	WSADATA  wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "WSAStartup error:" << GetLastError() << endl;
		return false;
	}

	// socket对象
	m_Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (m_Socket == INVALID_SOCKET)
	{
		closesocket(m_Socket);
		m_Socket = INVALID_SOCKET;
		return false;
	}

	// 远端地址
	const char* ip = "121.248.50.92";
	int	port = 8888;
	m_RemoteAddress.sin_family = AF_INET;
	m_RemoteAddress.sin_port = htons(port);
	m_RemoteAddressLen = sizeof(m_RemoteAddress);
	inet_pton(AF_INET, ip, &m_RemoteAddress.sin_addr);

	// 接收和发送
	char recvBuf[1024] = { 0 };
	//char sendBuf[1024] = "Nice to meet you!";

	int sendLen = sendto(m_Socket, (char*)&spa, sizeof(SPA)
		, 0, (sockaddr*)&m_RemoteAddress, m_RemoteAddressLen);
	for (int i = 0; i < 100; i++) {
		int sendLen = sendto(m_Socket, (char*)&spa, sizeof(SPA)
			, 0, (sockaddr*)&m_RemoteAddress, m_RemoteAddressLen);
		cout << i << " ";
	}
	if (sendLen > 0) {
		std::printf("发送到远程端连接, 其ip: %s, port: %d\n", inet_ntoa(m_RemoteAddress.sin_addr), ntohs(m_RemoteAddress.sin_port));
		std::cout << "发送到远程端的信息： " << spa.userID.bits[0] << " "
			<< spa.nonce << " "
			<< spa.timeStamp << " "
			<< spa.sourceIP << " "
			<< spa.name << " "
			<< spa.type << " "
			<< sizeof(spa)
			<< endl;
	}

	//int recvLen = recvfrom(m_Socket, recvBuf, 1024, 0, NULL, NULL);
	//if (recvLen > 0) {
	//	std::printf("接收到一个连接, 其ip: %s, port: %d\n", inet_ntoa(m_RemoteAddress.sin_addr), ntohs(m_RemoteAddress.sin_port));
	//	std::cout << "接收到一个信息： " << recvBuf << endl;
	//}

	////接着对gateway发送SPA包
	//char* gatewayIP = "127.0.0.1";
	//port = spa.destPort;
	//m_RemoteAddress.sin_port = htons(port);
	//inet_pton(AF_INET, ip, &m_RemoteAddress.sin_addr);
	//sendLen = sendto(m_Socket, (char*)&spa, sizeof(SPA)
	//	, 0, (sockaddr*)&m_RemoteAddress, m_RemoteAddressLen);
	//if (sendLen > 0) {
	//	std::printf("发送到远程端连接, 其ip: %s, port: %d\n", inet_ntoa(m_RemoteAddress.sin_addr), ntohs(m_RemoteAddress.sin_port));
	//	std::cout << "发送到远程端的信息： " << spa.userID.bits[0] << " "
	//		<< spa.nonce << " "
	//		<< spa.timeStamp << " "
	//		<< spa.sourceIP << " "
	//		<< sizeof(spa)
	//		<< endl;
	//}

	closesocket(m_Socket);
	WSACleanup();
	return true;
}

int main() {
	struct SPA spa;
	//初始化数据包
	int status = initialSPA(&spa);
	if (status != true) {
		return -1;
	}
	cout << spa.destPort << endl;
	//向控制器发送数据包
	status = SPA2controller(spa);
	if (status != true)
	{
		return -1;
	}
	//cout << myadd(3, 4) << endl;
	return true;
}
