#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void errif(bool condition, const char *errmsg){
    if(condition){
        perror(errmsg);
        exit(EXIT_FAILURE);
    }
}


char** convertToArgv(const std::vector<std::string>& vec, int& argc)
{
    char** argv = NULL;
    argc = vec.size();
    if (argc > 0)
    {
        argv = (char**)malloc((argc + (size_t)1) * sizeof(char*)); /* 注意: 要多分配一个单元空间 */
        if (argv)
        {
            for (int i = 0; i < argc; ++i)
            {
                const auto& str = vec[i];
                argv[i] = (char*)malloc((str.size() + (size_t)1) * sizeof(char));
                if (argv[i])
                {
                    memcpy(argv[i], str.c_str(), str.size());
                    argv[i][str.size()] = '\0';
                }
            }
            argv[argc] = NULL; /* 注意: 最后一个元素要设置为空指针 */
        }
    }
    return argv;
}

void destroyArgv(int argCount, char** argList) {
    for (int i = 0; i < argCount; i++) {
        free(argList[i]);  // 释放每个参数字符串的内存
    }
    free(argList);  // 释放参数列表的内存
}

std::string getCurrentTime(){
    time_t now = time(NULL);
	tm* tm_t = localtime(&now);
	std::stringstream ss;
	ss << tm_t->tm_mon + 1 << "/" << tm_t->tm_mday << "/" 
    << tm_t->tm_year + 1900 <<"-"<< tm_t->tm_hour << ":" << tm_t->tm_min << ":" << tm_t->tm_sec;
    return ss.str();
}