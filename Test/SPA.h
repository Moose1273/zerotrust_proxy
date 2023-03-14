#include <cstdint>
#include <ctime>
#include<iostream>
#ifndef _SPA_H_
#define _SPA_H_
struct uint256_t
{
	uint64_t bits[4];
};
struct uint128_t
{
	uint64_t bits[2];
};
#pragma once
/// <summary>
/// sizeof(SPA) == 140
/// </summary>
struct SPA
{
	uint256_t userID;								//用户ID
	uint256_t deviceID;								//设备ID
	time_t timeStamp;								//时间戳
	uint64_t nonce;									//随机数
	uint32_t sourceIP;								//源IP
	uint32_t destPort;								//目标端口号
	uint128_t HMAC;									//HMAC
	char name[32];									//请求的服务
	char type[32];									//请求的服务类型
};

uint32_t getSourceIP();
int initialSPA(struct SPA* spa);
int SPA2controller(SPA& spa);

//int myadd(int a, int b);
#endif/*include _SPA_H_*/

