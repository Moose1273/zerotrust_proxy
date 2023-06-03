import subprocess
import json
import windows.WinBaselineCheck as WinBaselineCheck
import windows.win_patch_vul as win_patch_vul
import linux.LinuxBaselineCheck as LinuxBaselineCheck
# PowerShell脚本文件路径
# 安全配置检查
baseline_check_file_path = r'windows/win_baseline_check.ps1'
# 软件漏洞检查
software_vul_file_path = r'windows/win-inventory-vul.ps1'
#windows检查结果check_res文件
# 安全检查结果
win_res = 'windows/win_res.json'
# 软件检查结果
win_inventory_res = 'windows/win_inventory_res.json'
# 系统检查结果
systeminfo = 'windows/systeminfo.txt'
# Linux脚本文件路径
# 安全配置检查
sh_file_path = r'linux/linux_baseline_check.sh'

linux_res_path = 'linux/linux_res.json'

import platform
import subprocess
# 获取操作系统类型
os_type = platform.system()
# ==========================================================================
# MAIN PROGRAM
# ==========================================================================
if __name__ == '__main__':
    final_result = 0
    if os_type == 'Windows':
        # 用于检查系统安全配置
        try:
            p = subprocess.run(['powershell', '-Command',
                       f'Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File {baseline_check_file_path}" -Verb RunAs '])
        except subprocess.CalledProcessError as error:
            print(f"{baseline_check_file_path} execution failed with error code {error.returncode} and error message: {error.stderr}")
        else:
            print(f"{baseline_check_file_path} executed successfully.")

        # 用于检测windows系统软件漏洞情况
        try:
            p = subprocess.run(['powershell', '-Command',
                       f'Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File {software_vul_file_path}" -Verb RunAs -WindowStyle Hidden'])#  -WindowStyle Hidden用于后台运行ps
        except subprocess.CalledProcessError as error:
            print(f"{software_vul_file_path} execution failed with error code {error.returncode} and error message: {error.stderr}")
        else:
            print(f"{software_vul_file_path} executed successfully.")

        # 处理win安全配置检查情况
        with open(win_res, 'r', encoding='utf-8-sig') as file:
            json_str = file.read()        
        data = json.loads(json_str)
        win_os_check_score = WinBaselineCheck.windows_scan_res_report(data)
        file.close()

        # 处理win软件漏洞检查情况
        with open(win_inventory_res, 'r', encoding='utf-8-sig') as file:
            inventory_json_str = file.read()
        inventory_data = json.loads(inventory_json_str)
        cvssv2_basescore = WinBaselineCheck.windows_inventory_scan_res_report(inventory_data)
        file.close()

        # 用于检测windows系统漏洞情况，使用KB补丁，下载Windows的definitions漏洞包，查询缺省补丁以及对应漏洞
        cvssv2_osvul_score = win_patch_vul.windows_os_vul_res_report(systeminfo)

        # 处理评级
        final_result = max(win_os_check_score, cvssv2_basescore, cvssv2_osvul_score)

    elif os_type == 'Linux':
        # Linux系统，运行linux_baseline_check.sh
        subprocess.run(['sudo', '/bin/bash', f'{sh_file_path}'])
        with open(linux_res_path, 'r') as file:
            json_str = file.read()

        # 解析 JSON 字符串为 Python 字典对象
        data = json.loads(json_str)

        # 获取主机上软件安全漏洞情况
        LinuxBaselineCheck.getProductList()

        # 处理安全漏洞检测结果
        LinuxBaselineCheck.linux_scan_res_report(data)

        # 计算安全基线评级
        final_result = LinuxBaselineCheck.calculateScore()
        file.close()
    else:
        # 不支持的操作系统类型
        print('Unsupported operating system.')
    
    # 判断os安全级别
    Severity = 'None'
    if final_result == 4:
        Severity = 'Critical'
    elif 3 <= final_result:
        Severity = 'Important'
    elif 2 <= final_result:
        Severity = 'Low'
    elif 1 <= final_result:
        Severity = 'Moderate'
    else:
        Severity = 'None'
