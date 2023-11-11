#include "logger.h"

//引用main中的全局日志变量logFile
extern FILE* logFile;
int onAlertCallback(st_alert_info info)
{
    INFO_LOG(logFile, "时间：%s, 协议: %s, 源地址: %s:%d, 目的地址: %s:%d, 等级: %d, 类别: %s, 消息: %s", info.timebuf, info.protocol, info.srcIp, info.srcPort,
             info.dstIp, info.dstPort, info.priority, info.classification, info.msg);
    return 1;
}

