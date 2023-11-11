
#include <thread>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "proxy.h"
#include "SDP_security_Proxy.h"
#include "logger.h"
#include "util.h"

/* 定义全局日志文件 */
FILE* logFile;

// 子进程的进程ID
pid_t  childPid;
// 信号处理函数
void signalHandler( int signum) {
    if (signum == SIGUSR1) {
        // 接收到 SIGUSR1 信号，向子进程发送结束信号
        kill(childPid, SIGINT);
    }
}

int main(int argc, char* argv[])
{
    // 打开日志文件以进行写入
    logFile = fopen("./SDP_Proxy_log.txt", "a+");
    if (logFile == NULL) {
        printf("无法打开日志文件\n");
        return -1;
    }
    /* 设置告警回调 */
    setAlarmCallback(onAlertCallback); 
    /* 创建参数列表 */
    int argCount = 0;
    std::vector<std::string> s_argVec;
    char** argList = NULL;
    {
        s_argVec.clear();
        s_argVec.emplace_back(argv[0]);
        s_argVec.emplace_back("-c");
        s_argVec.emplace_back("suricata/suricata/suricata.yaml");
        s_argVec.emplace_back("-q");
        s_argVec.emplace_back("0");
        argList = convertToArgv(s_argVec, argCount);
    }
    // 注册信号处理函数
    signal(SIGUSR1, signalHandler);
    /* 启动suricata */
    if (argCount > 0 && argList)
    {
        // 创建子进程
        childPid = fork();
        if (childPid == -1) {
            // 创建子进程失败
            printf("Failed to create child process.\n");
            return 1;
        } else if (childPid == 0) {
            // 用子进程来执行Suricata进程
            startSuricata(argCount, argList); 
            return 0;
        }else {
            /* 销毁删除列表,free space */
            destroyArgv(argCount, argList);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            int status;
            std::string state;
            do{
                status = SDP_Proxy(logFile);
                if(status){
                    printf("本次SDP会话已结束， 输入\"continue\"以发起下一次SDP会话\n");
                }
                cin>>state;
            }while(state.compare("continue") == 0);
            /* 关闭suricata */
            kill(childPid, SIGUSR1);
            printf("ending sdp proxy...\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            /* 关闭日志文件 */
            fclose(logFile);
        }
    }
    return 0;
}
