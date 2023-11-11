#ifndef PROXY_H
#define PROXY_H
#include <stdio.h>
#include <string.h>
#include <string.h>
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
    /** 
     * @brief 启动Suricata
     */
    void startSuricata(int argc, char** argv);

    /** 
     * @brief 停止Suricata
     */
    void stopSuricata();
#ifdef __cplusplus
}
#endif
#endif
