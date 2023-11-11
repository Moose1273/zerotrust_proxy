#ifndef LOGGER_H
#define LOGGER_H
#pragma once
#include <stdio.h>
#include "../suricata/suricata/src/alert-define.h"

/** 
 * @brief 告警日志记录
 */
#define INFO_LOG(logFile, format, ...) {fprintf(logFile, "[INFO] " format "\n", ##__VA_ARGS__); fflush(logFile);}

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief 响应告警回调
     * @param info 告警信息
     * @return 0-不写日志, 1-写日志
     */
    int onAlertCallback(st_alert_info info);

    
#ifdef __cplusplus
}
#endif
#endif
