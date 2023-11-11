#ifndef UTIL_H
#define UTIL_H
#pragma once
#include <string>
#include <vector>
#include<time.h> 
#include <sstream>
    /**
     * @brief 错误输出
     * @param condition 错误代码
     * @param errmsg 错误信息输出
     */ 
    void errif(bool condition, const char *errmsg);

    /**
     * @brief 把字符串数组转换为参数列表
     * @param vec 字符串数组
     * @param argc [输出]参数个数
     * @return 参数列表(需要外部调用free释放内存)
     */
    char** convertToArgv(const std::vector<std::string>& vec, int& argc);

    /**
     * @brief 释放动态申请的空间
     * @param argCount 需要释放的数组大小
     * @param argList 需要释放的数组
     */
    void destroyArgv(int argCount, char** argList);

    /**
     * @brief 获取当前系统时间
     * @return 当前时间
     */
  std::string getCurrentTime();

    /* 
     * 一些socket状态码，待扩充
    */
    /* 错误类 */
    #define INVALID_SOCKET -2
    #define SOCKET_ERROR -1
    #define TIMEOUT_ERROR -3
    /* 正常运行类 */
    #define SOCKET_SUCCESS 1
    #define SOCKET_PENDING 2

#endif