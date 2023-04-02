#include <cstdint>
#include <ctime>
#include <bitset>
#include<iostream>
#ifndef _SPA_H_
#define _SPA_H_
#pragma once



#pragma once
/// <summary>
/// sizeof(SPA) == 140
/// </summary>
struct SPA
{
	uint32_t ip_address;							//源IP
	time_t timestamp;								//时间戳
	std::bitset<32> random_num;						//随机数
	std::bitset<32> message_type;					//消息类型
	std::bitset<96> default_value;       			//缺省值
	std::bitset<256> userID;						//用户ID
	std::bitset<256> deviceID;						//设备ID
	std::bitset<256> HOTP;							//HOTP,基于HMAC的一次性密码
	std::bitset<256> hmac;							//HMAC
	char name[32];									//请求的服务
	char type[32];									//请求的服务类型
};

uint32_t getSourceIP();
bool initialSPA(struct SPA* spa);

#endif/*include _SPA_H_*/

