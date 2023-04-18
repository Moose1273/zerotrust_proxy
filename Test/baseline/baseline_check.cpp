#include "baseline_check.h"

int main() {
    // 要运行的 sh 脚本路径
    const char* scriptPath = "./linux_baseline_check.sh";

    // 构造要执行的命令
    std::string command = "sudo  ";
    command += scriptPath;

    // 使用 system 函数执行命令
    int result = system(command.c_str());
    if (result == -1) {
        std::cerr << "Failed to execute command: " << command << std::endl;
        return EXIT_FAILURE;
    }

    // 检查命令的退出码
    if (WIFEXITED(result)) {
        int exitCode = WEXITSTATUS(result);
        if (exitCode == 0) {
            std::cout << "linux_baseline_check.sh executed successfully." << std::endl;
        } else {
            std::cerr << "linux_baseline_check.sh failed with exit code " << exitCode << "." << std::endl;
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "linux_baseline_check.sh failed to execute." << std::endl;
        return EXIT_FAILURE;
    }
    // 调用Python解释器并执行Python文件，并将输出读取到缓冲区中
    FILE* pipe = popen("python3 LinuxBaselineCheck.py", "r");
    if (!pipe) {
        std::cerr << "Failed to open pipe." << std::endl;
        return 1;
    }

    char buffer[128];
    std::string output = "";
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    // 关闭管道
    pclose(pipe);

    //可以在这里写数据分析的模块
    // 输出获取的数据
    std::cout << "Data from Python: " << output << std::endl;
    
    return 0;
}
