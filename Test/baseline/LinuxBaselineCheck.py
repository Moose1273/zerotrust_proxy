import sys
import argparse
import json
from multiprocessing import Process
import subprocess
pV = sys.version_info[0]
if pV == 2:
    import urllib2
else:
    import requests


#==========================================================================
# GLOBAL VARIABLES
#==========================================================================
productList = []
queryData = ""
exploit_sum = 0
__version__ = 2.2

os_check_sum = 77
pass_Num = 0
cvssv2_basescore_sum = 0
os_check_score = 0

def getProductList():
	global productList

	# 根据内核类型设置 dpkg 变量
	with open('/proc/version', 'r') as f:
		dist_name = f.read()
	#dist_name = platform.uname()

	if 'debian' in dist_name.lower() or 'ubuntu' in dist_name.lower():
		dpkg = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n'"
	elif 'redhat' in dist_name.lower() or 'centos' in dist_name.lower() or 'rhel' in dist_name.lower():
		dpkg = "rpm -qa --queryformat='%{NAME} %{VERSION} %{ARCH}\\n'"
	else:
		print("无法确定当前使用的内核")
	#dpkg = "dpkg-query -W -f='${Package} ${Version} ${Architecture}\n'"
	action = subprocess.Popen(dpkg, shell = True, stdout = subprocess.PIPE)
	results = action.communicate()[0]
	if pV == 2:
		tempList = str(results).split('\n')
	else:
		tempList = str(results).split('\\n')
	for i in range(0,len(tempList)-1):
		productList.append(tempList[i].split(" "))

def linux_scan_res_report(scanResDict={}):
    global pass_Num
    global os_check_score
    linuxScanResDict=scanResDict['os_scan_result']
    #middlewareCheckResDict=scanResDict['middleware_check_result']
    # print(middlewareCheckResDict)
    #linuxVulnScanResDict=scanResDict['vuln_scan_result']

    # 通过vulmon收集漏洞信息
    #vulnCheck(data=productList)

    # 从dict数据中解析并读取数据
    basic_info=linuxScanResDict['basic_info']
    # scanTime=basic_info['scanTime']
    # hostname=basic_info['hostname']
    # macaddr=basic_info['macaddr']
    # ipList=basic_info['ipList']
    # kernelVersion=basic_info['kernelVersion']
    # osVersion=basic_info['osVersion']
    init_check_res=linuxScanResDict['init_check_res']
    tmp_partition_info=init_check_res['tmp_partition_info']
    tmpIfSeparate=tmp_partition_info['tmpIfSeparate']
    if tmpIfSeparate == "True":
        pass_Num += 1
    tmpIfNoexec=tmp_partition_info['tmpIfNoexec']
    if tmpIfNoexec == "True":
        pass_Num += 1
    tmpIfNosuid=tmp_partition_info['tmpIfNosuid']
    if tmpIfNosuid == "True":
        pass_Num += 1
    boot_secure_info=init_check_res['boot_secure_info']
    grubcfgIfExist=boot_secure_info['grubcfgIfExist']
    grubcfgPermission=boot_secure_info['grubcfgPermission']
    if grubcfgIfExist == "True" and int(grubcfgPermission) <= 600:
        pass_Num += 1
    grubcfgIfSetPasswd=boot_secure_info['grubcfgIfSetPasswd']
    if grubcfgIfExist == "True" and grubcfgIfSetPasswd == "True":
        pass_Num += 1
    singleUserModeIfNeedAuth=boot_secure_info['singleUserModeIfNeedAuth']
    if singleUserModeIfNeedAuth == "True":
        pass_Num += 1
    selinuxStateIfEnforcing=boot_secure_info['selinuxStateIfEnforcing']
    if selinuxStateIfEnforcing == "True":
        pass_Num += 1
    selinuxPolicyIfConfigured=boot_secure_info['selinuxPolicyIfConfigured']
    if selinuxPolicyIfConfigured == "True":
        pass_Num += 1
    service_check_res=linuxScanResDict['service_check_res']
    timeSyncServerIfConfigured=service_check_res['timeSyncServerIfConfigured']
    if timeSyncServerIfConfigured == "True":
        pass_Num += 1
    x11windowIfNotInstalled=service_check_res['x11windowIfNotInstalled']
    if x11windowIfNotInstalled == "True":
        pass_Num += 1
    network_check_res=linuxScanResDict['network_check_res']
    hostsAllowFileIfExist=network_check_res['hostsAllowFileIfExist']
    hostsAllowFilePermission=network_check_res['hostsAllowFilePermission']
    if hostsAllowFileIfExist == "True" and int(hostsAllowFilePermission) <= 644:
        pass_Num += 1
    hostsAllowFileIfConfigured=network_check_res['hostsAllowFileIfConfigured']
    if hostsAllowFileIfExist == "True" and hostsAllowFileIfConfigured == "True":
        pass_Num += 1
    hostsDenyFileIfExist=network_check_res['hostsDenyFileIfExist']
    hostsDenyFilePermission=network_check_res['hostsDenyFilePermission']
    if hostsDenyFileIfExist == "True" and int(hostsDenyFilePermission) <= 644:
        pass_Num += 1
    hostsDenyFileIfConfigured=network_check_res['hostsDenyFileIfConfigured']
    if hostsDenyFileIfExist == "True" and hostsDenyFileIfConfigured == "True":
        pass_Num += 1
    iptablesIfInstalled=network_check_res['iptablesIfInstalled']
    if iptablesIfInstalled == "True":
        pass_Num += 1
    iptablesInputPolicyIfDrop=network_check_res['iptablesInputPolicyIfDrop']
    if iptablesIfInstalled == "True" and iptablesInputPolicyIfDrop == "True":
        pass_Num += 1
    iptablesOutputPolicyIfDrop=network_check_res['iptablesOutputPolicyIfDrop']
    if iptablesIfInstalled == "True" and iptablesOutputPolicyIfDrop == "True":
        pass_Num += 1
    auditd_check_res=linuxScanResDict['auditd_check_res']
    auditd_config_info=auditd_check_res['auditd_config_info']
    auditdIfEnabled=auditd_config_info['auditdIfEnabled']
    if auditdIfEnabled == "True":
        pass_Num += 1
    auditdconfIfExist=auditd_config_info['auditdconfIfExist']
    auditdIfSetMaxLogFile=auditd_config_info['auditdIfSetMaxLogFile']
    if auditdconfIfExist == "True" and auditdIfSetMaxLogFile != "False" and int(auditdIfSetMaxLogFile) >= 8:
        pass_Num += 1
    auditdIfSetMaxLogFileAction=auditd_config_info['auditdIfSetMaxLogFileAction']
    if auditdconfIfExist == "True" and ("keep_logs" in auditdIfSetMaxLogFileAction.lower() or "rotate" in auditdIfSetMaxLogFileAction.lower()):
        pass_Num += 1
    auditdIfSetSpaceLeftAction=auditd_config_info['auditdIfSetSpaceLeftAction']
    if auditdconfIfExist == "True" and "ignore" not in auditdIfSetSpaceLeftAction.lower() and "rotate" not in auditdIfSetSpaceLeftAction.lower():
        pass_Num += 1
    auditdIfSetNumLogs=auditd_config_info['auditdIfSetNumLogs']
    if auditdconfIfExist == "True" and int(auditdIfSetNumLogs) >= 5:
        pass_Num += 1
    auditd_rules_info=auditd_check_res['auditd_rules_info']
    if auditdIfEnabled == "True":
        pass_Num += 1
    auditdRulesIfExist=auditd_rules_info['auditdRulesIfExist']
    auditdRulesIfNotNull=auditd_rules_info['auditdRulesIfNotNull']
    auditdIfCheckTimechange=auditd_rules_info['auditdIfCheckTimechange']
    if auditdRulesIfNotNull == "True" and auditdIfCheckTimechange == "True":
        pass_Num += 1
    auditdRulesCheckedUserandgroupfile=auditd_rules_info['auditdRulesCheckedUserandgroupfile']
    auditdRulesNotCheckedUserandgroupfile=auditd_rules_info['auditdRulesNotCheckedUserandgroupfile']
    if auditdRulesIfNotNull == "True"  and len(auditdRulesNotCheckedUserandgroupfile) == 0:
        pass_Num += 1
    auditdRulesCheckedNetworkenv=auditd_rules_info['auditdRulesCheckedNetworkenv']
    auditdRulesNotCheckedNetworkenv=auditd_rules_info['auditdRulesNotCheckedNetworkenv']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedNetworkenv) == 0:
        pass_Num += 1
    auditdRulesCheckedMACchange=auditd_rules_info['auditdRulesCheckedMACchange']
    auditdRulesNotCheckedMACchange=auditd_rules_info['auditdRulesNotCheckedMACchange']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedMACchange) == 0:
        pass_Num += 1
    auditdRulesCheckedLoginoutEvents=auditd_rules_info['auditdRulesCheckedLoginoutEvents']
    auditdRulesNotCheckedLoginoutEvents=auditd_rules_info['auditdRulesNotCheckedLoginoutEvents']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedMACchange) == 0:
        pass_Num += 1
    auditdRulesCheckedDACChangeSyscall=auditd_rules_info['auditdRulesCheckedDACChangeSyscall']
    auditdRulesNotCheckedDACChangeSyscall=auditd_rules_info['auditdRulesNotCheckedDACChangeSyscall']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedDACChangeSyscall) == 0:
        pass_Num += 1
    auditdRulesCheckedFileAccessAttemptSyscall=auditd_rules_info['auditdRulesCheckedFileAccessAttemptSyscall']
    auditdRulesNotCheckedFileAccessAttemptSyscall=auditd_rules_info['auditdRulesNotCheckedFileAccessAttemptSyscall']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedFileAccessAttemptSyscall) == 0:
        pass_Num += 1
    auditdRulesCheckedPrivilegedCommand=auditd_rules_info['auditdRulesCheckedPrivilegedCommand']
    auditdRulesNotCheckedPrivilegedCommand=auditd_rules_info['auditdRulesNotCheckedPrivilegedCommand']
    if auditdRulesIfNotNull == "True" and len(auditdRulesCheckedPrivilegedCommand) == 0:
        pass_Num += 1
    auditdRulesCheckedSudoerFile=auditd_rules_info['auditdRulesCheckedSudoerFile']
    auditdRulesNotCheckedSudoerFile=auditd_rules_info['auditdRulesNotCheckedSudoerFile']
    if auditdRulesIfNotNull == "True" and len(auditdRulesNotCheckedSudoerFile) == 0:
        pass_Num += 1
    auditdRulesIfImmutable=auditd_rules_info['auditdRulesIfImmutable']
    if auditdRulesIfNotNull == "True" and auditdRulesIfImmutable == "True":
        pass_Num += 1
    log_check_res=linuxScanResDict['log_check_res']
    rsyslogIfEnabled=log_check_res['rsyslogIfEnabled']
    if rsyslogIfEnabled == "True":
        pass_Num += 1
    authentication_check_res=linuxScanResDict['authentication_check_res']
    crond_config_info=authentication_check_res['crond_config_info']
    crondIfEnabled=crond_config_info['crondIfEnabled']
    if crondIfEnabled == "True":
        pass_Num += 1
    crondConfigFilenameArray=crond_config_info['crondConfigFilenameArray']
    crondConfigFilePermissionArray=crond_config_info['crondConfigFilePermissionArray']
    pass_Num += 1
    for fPerm in crondConfigFilePermissionArray.split(";"):
        if len(fPerm) != 0:
            if "False" in fPerm or int(fPerm) > 700:
                pass_Num -= 1
                break
    crondallowdenyFilenameArray=crond_config_info['crondallowdenyFilenameArray']
    crondallowdenyFileIfExistArray=crond_config_info['crondallowdenyFileIfExistArray']
    crondallowdenyFilePermissionArray=crond_config_info['crondallowdenyFilePermissionArray']
    pass_Num += 1
    for fPerm in crondallowdenyFilePermissionArray.split(";"):
        if len(fPerm) != 0:
            if "False" in fPerm or int(fPerm) > 700:
                pass_Num -= 1
    crondallowdenyFileOwnerArray=crond_config_info['crondallowdenyFileOwnerArray']
    sshd_config_info=authentication_check_res['sshd_config_info']
    sshdIfEnabled=sshd_config_info['sshdIfEnabled']
    sshdConfigFilePermission=sshd_config_info['sshdConfigFilePermission']
    if sshdIfEnabled != "True" or sshdConfigFilePermission != "False" and int(sshdConfigFilePermission) <= 600:
        pass_Num += 1
    sshdIfDisableX11forwarding=sshd_config_info['sshdIfDisableX11forwarding']
    if sshdIfEnabled != "True" or sshdIfDisableX11forwarding == "True":
        pass_Num += 1
    sshdIfSetMaxAuthTries=sshd_config_info['sshdIfSetMaxAuthTries']
    if sshdIfEnabled != "True" or sshdIfSetMaxAuthTries != "False" and int(sshdIfSetMaxAuthTries) >= 4:
        pass_Num += 1
    sshdIfEnableIgnoreRhosts=sshd_config_info['sshdIfEnableIgnoreRhosts']
    if sshdIfEnabled != "True" or sshdIfEnableIgnoreRhosts == "True":
        pass_Num += 1
    sshdIfDisableHostbasedAuthentication=sshd_config_info['sshdIfDisableHostbasedAuthentication']
    if sshdIfEnabled != "True" or sshdIfDisableHostbasedAuthentication == "True":
        pass_Num += 1
    sshdIfDisablePermitRootLogin=sshd_config_info['sshdIfDisablePermitRootLogin']
    if sshdIfEnabled != "True" or sshdIfDisablePermitRootLogin == "True":
        pass_Num += 1
    sshdIfDisablePermitEmptyPasswords=sshd_config_info['sshdIfDisablePermitEmptyPasswords']
    if sshdIfEnabled != "True" or sshdIfDisablePermitEmptyPasswords == "True":
        pass_Num += 1
    sshdIfDisablePermitUserEnvironment=sshd_config_info['sshdIfDisablePermitUserEnvironment']
    if sshdIfEnabled != "True" or sshdIfDisablePermitUserEnvironment == "True":
        pass_Num += 1
    sshdIfSpecificMACs=sshd_config_info['sshdIfSpecificMACs']
    if sshdIfEnabled != "True" or sshdIfSpecificMACs == "True":
        pass_Num += 1
    sshdIfSetClientAliveInterval=sshd_config_info['sshdIfSetClientAliveInterval']
    if sshdIfEnabled != "True" or sshdIfSetClientAliveInterval != "False" and int(sshdIfSetClientAliveInterval) <= 180:
        pass_Num += 1
    sshdIfSetLoginGraceTime=sshd_config_info['sshdIfSetLoginGraceTime']
    if sshdIfEnabled != "True" or sshdIfSetLoginGraceTime != "False" and int(sshdIfSetLoginGraceTime) <= 120:
        pass_Num += 1
    pam_config_info=authentication_check_res['pam_config_info']
    pamPwqualityconfIfExist=pam_config_info['pamPwqualityconfIfExist']
    pamIfSetMinlen=pam_config_info['pamIfSetMinlen']
    if pamIfSetMinlen != "False" and int(pamIfSetMinlen) >= 8:
        pass_Num += 1
    pamIfSetMinclass=pam_config_info['pamIfSetMinclass']
    if pamIfSetMinclass != "False" and int(pamIfSetMinclass) >= 3:
        pass_Num += 1
    sshdSetedLockAndUnlockTimeFiles=pam_config_info['sshdSetedLockAndUnlockTimeFiles']
    sshdNotSetedLockAndUnlockTimeFiles=pam_config_info['sshdNotSetedLockAndUnlockTimeFiles']
    if len(sshdNotSetedLockAndUnlockTimeFiles) == 0:
        pass_Num += 1
    sshdPamdFileArray=pam_config_info['sshdPamdFileArray']
    sshdPamdFileReuseLimitArray=pam_config_info['sshdPamdFileReuseLimitArray']
    if "False" not in sshdPamdFileReuseLimitArray and "False" not in [int(i) > 5 for i in sshdPamdFileReuseLimitArray.split(";")[:-1]]:
        pass_Num += 1
    sshdPamdFileIfSetSha512Array=pam_config_info['sshdPamdFileIfSetSha512Array']
    if "False" not in sshdPamdFileIfSetSha512Array:
        pass_Num += 1
    account_config_info=authentication_check_res['account_config_info']
    accountPassMaxDays=account_config_info['accountPassMaxDays']
    if len(accountPassMaxDays) != 0 and int(accountPassMaxDays)  <= 90:
        pass_Num += 1
    accountPassMinDays=account_config_info['accountPassMinDays']
    if len(accountPassMinDays) != 0 and int(accountPassMinDays)  >= 1:
        pass_Num += 1
    accountPassWarnDays=account_config_info['accountPassWarnDays']
    if len(accountPassWarnDays) != 0 and int(accountPassWarnDays)  >= 7:
        pass_Num += 1
    accountPassAutolockInactiveDays=account_config_info['accountPassAutolockInactiveDays']
    if len(accountPassAutolockInactiveDays) != 0 and int(accountPassAutolockInactiveDays) != -1:
        pass_Num += 1
    accountShouldUnloginArray=account_config_info['accountShouldUnloginArray']
    if len(accountShouldUnloginArray) == 0:
        pass_Num += 1
    accountGIDOfRoot=account_config_info['accountGIDOfRoot']
    if int(accountGIDOfRoot) == 0:
        pass_Num += 1
    accountProfileFileArray=account_config_info['accountProfileFileArray']
    accountProfileTMOUTArray=account_config_info['accountProfileTMOUTArray']
    if "False" not in accountProfileTMOUTArray and "False" not in [int(i) <= 900 for i in accountProfileTMOUTArray.split(";")[:-1]]:
        pass_Num += 1
    accountIfSetUsersCanAccessSuCommand=account_config_info['accountIfSetUsersCanAccessSuCommand']
    if "False" not in accountIfSetUsersCanAccessSuCommand:
        pass_Num += 1
    system_check_res=linuxScanResDict['system_check_res']
    file_permission_info=system_check_res['file_permission_info']
    importantFilenameArray=file_permission_info['importantFilenameArray']
    importantFilePermissionArray=file_permission_info['importantFilePermissionArray']
    tmpCount=0
    for i in importantFilePermissionArray.split(";")[:-1]:
        if i == "0000":
            tmpCount = tmpCount + 1
        if int(i) <= 644 :
            tmpCount = tmpCount + 1
    if tmpCount == 12:
        pass_Num += 1
    importantFileUidgidArray=file_permission_info['importantFileUidgidArray']
    if "False" not in ["0 0" == i for i in importantFileUidgidArray.split(";")[:-1]]:
        pass_Num += 1
    usergroup_config_info=system_check_res['usergroup_config_info']
    userIfSetPasswdOrArray=usergroup_config_info['userIfSetPasswdOrArray']
    if userIfSetPasswdOrArray == "True":
        pass_Num += 1
    uid0OnlyRootOrArray=usergroup_config_info['uid0OnlyRootOrArray']
    if uid0OnlyRootOrArray == "True":
        pass_Num += 1
    pathDirIfNotHasDot=usergroup_config_info['pathDirIfNotHasDot']
    if pathDirIfNotHasDot == "True":
        pass_Num += 1
    pathDirPermissionHasGWArray=usergroup_config_info['pathDirPermissionHasGWArray']
    if len(pathDirPermissionHasGWArray) == 0:
        pass_Num += 1
    pathDirPermissionHasOWArray=usergroup_config_info['pathDirPermissionHasOWArray']
    if len(pathDirPermissionHasOWArray) == 0:
        pass_Num += 1
    pathDirOwnerIsNotRootArray=usergroup_config_info['pathDirOwnerIsNotRootArray']
    pathDirDoesNotExistOrNotDirArray=usergroup_config_info['pathDirDoesNotExistOrNotDirArray']
    if len(pathDirDoesNotExistOrNotDirArray) == 0:
        pass_Num += 1
    userArray=usergroup_config_info['userArray']
    userHomeDirIfExistArray=usergroup_config_info['userHomeDirIfExistArray']
    if "False" not in userHomeDirIfExistArray:
        pass_Num += 1
    userHomeDirPermissionArray=usergroup_config_info['userHomeDirPermissionArray']
    if "False" not in userHomeDirPermissionArray and "False" not in [int(i) > 750 for i in userHomeDirPermissionArray.split(";")[:-1]]:
        pass_Num += 1
    userIfOwnTheirHomeDirArray=usergroup_config_info['userIfOwnTheirHomeDirArray']
    if "False" not in userIfOwnTheirHomeDirArray:
        pass_Num += 1
    userHomeDirIfHasGWorOWDotFileArray=usergroup_config_info['userHomeDirIfHasGWorOWDotFileArray']
    if "False" not in userHomeDirIfHasGWorOWDotFileArray:
        pass_Num += 1
    userHomeDirIfHasOtherFileArray=usergroup_config_info['userHomeDirIfHasOtherFileArray']
    if "False" not in userHomeDirIfHasOtherFileArray:
        pass_Num += 1
    groupNotExistInetcgroup=usergroup_config_info['groupNotExistInetcgroup']
    if len(groupNotExistInetcgroup) == 0:
        pass_Num += 1
    usersIfHasUniqueUIDArray=usergroup_config_info['usersIfHasUniqueUIDArray']
    if len(usersIfHasUniqueUIDArray) == 0:
        pass_Num += 1
    groupsIfHasUniqueGIDArray=usergroup_config_info['groupsIfHasUniqueGIDArray'] 
    if len(groupsIfHasUniqueGIDArray) == 0:
        pass_Num += 1
    os_check_score = (os_check_sum - pass_Num)/os_check_sum*100
    #print("os check score is:",os_check_score)

# def linux_vuln_check_res_store(data={}):
#     basic_info=data['basic_info']
#     scanTime=basic_info['scanTime']
#     hostname=basic_info['hostname']
#     macaddr=basic_info['macaddr']
#     ipList=basic_info['ipList']
#     # kernelVersion=basic_info['kernelVersion']
#     osVersion=basic_info['osVersion']
#     linux_vuln_scan_res=data['vuln_scan_res']
#     os=linux_vuln_scan_res['os']
#     arc=linux_vuln_scan_res['arc']
#     linux_vuln_scan_list=linux_vuln_scan_res['vulnScanList']
#     # linux_vuln_scan_list=[["kbd", "1.15.5", "Centos"], ["setup", "2.8.71", "Centos"], ["libstdc++", "4.8.5", "Centos"]]
#     # os="Linux"
#     # arc="x86_64"
#     vulnCheckResList = vulnCheck(data=linux_vuln_scan_list,os=os,arc=arc)
#     #print("vulnCheckResList:"+ vulnCheckResList)
#     print("vulnCheckResList: {}".format(vulnCheckResList))
#     if len(vulnCheckResList) > 0:
#         print(bcolors.OKGREEN +"[+] search Linux Exp Success")
#         return vulnCheckResList
#     else:
#         print(bcolors.OKBLUE + "[-] no EXP or error")
# def args():
#     global args

#     description = "Host-based vulnerability scanner. Find installed packages on the host, ask their vulnerabilities to vulmon.com API and print vulnerabilities with available exploits. All found exploits can be downloaded by Vulmap."
#     parser = argparse.ArgumentParser('vulmap.py', description=description)
#     parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose mode', dest='verbose', required=False)
#     parser.add_argument('-o', '--only-exploitablevulns', action='store_true', default=False, help='Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.', dest='onlyexploitable', required=False)
#     parser.add_argument('-a', '--download-allexploits', action='store_true', default=False, help='Scans the computer and downloads all available exploits.', dest='exploit', required=False)
#     parser.add_argument('-d', '--download-exploit', type=str, default=False, help='Downloads given exploit. ./%(prog)s -d EDB16372', dest='exploit_ID', required=False)
#     parser.add_argument('-r', '--read-inventoryfile', type=str, default=False, nargs='?', const='inventory.json', help='Uses software inventory file rather than scanning local computer. ./%(prog)s -r pc0001.json', dest='InventoryOutFile', required=False)
#     parser.add_argument('-s', '--save-inventoryfile', type=str, default=False, nargs='?', const='inventory.json', help='Saves software inventory file. Enabled automatically when Mode is CollectInventory. ./%(prog)s -r pc0001.json', dest='InventoryInFile', required=False)
#     parser.add_argument('-c', '--collect-inventory', type=str, default=False, nargs='?', const='inventory.json', help='Collects software inventory but does not conduct a vulnerability scanning.Software inventory will be saved as inventory.json in default. ./%(prog)s -r pc0001.json', dest='CollectInventory', required=False)
#     parser.add_argument('-p', '--proxy', type=str, default=False, help='Specifies a proxy server. Enter the URI of a network proxy server. ./%(prog)s -p localhost:8080', dest='proxy', required=False)
#     parser.add_argument('-t', '--proxy-type', type=str, default=False, help='Specifies a proxy type ./%(prog)s -p https', dest='proxytype', required=False)
#     parser.add_argument('--version', action='version', version='%(prog)s version ' + str(__version__))
#     args = parser.parse_args()

def sendRequest(queryData,os="Linux",arc="x86_64"):
    product_list = '"product_list": ' + queryData

    json_request_data = '{'
    json_request_data += '"os": "' + os + '",'
    json_request_data += '"arc": "' + arc + '",'
    json_request_data += product_list
    json_request_data +=  '}'

    url = 'https://vulmon.com/scannerapi_vv211'
    body = 'querydata=' + json_request_data
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'cache-control': 'no-cache',
        'Pragma': 'no-cache'       
        }
    print("+=================body=======================")
    print(body)
    print("+==================body======================")
    if args.proxy:
        if args.proxytype == 'https':
            proxy = args.proxy
            proxies = {'http' : 'https://'+proxy, 'https' : 'https://'+proxy}
            response = (requests.post(url, data=body, headers=headers, proxies=proxies, verify=False)).json()
        else:
            proxy = args.proxy
            proxies = {'http' : proxy, 'https' : proxy}
            response = (requests.post(url, data=body, headers=headers, proxies=proxies, verify=False)).json()
    else:
            response = requests.post(url, data=body, headers=headers)
            if response.status_code == 200:
                response = response.json()
            else:
                response = {'status_message':'error'}
            print("+=================response.content=======================")
            print(response)
            print("+==================response.content======================")
    return response

def outResults(q,os="Linux",arc="x86_64"):
    global exploit_sum
    global cvssv2_basescore_sum
    queryData = q[:-1]
    queryData += ']'
    response = sendRequest(queryData,os=os,arc=arc)
    allProductExpList=[]
    if response['status_message'] == 'success':
        # 一个query_string
        for i in range(0, len(response["results"])):
            # allExpList=[]
            cveDictOfOneProduct={}
            tmpCVEList=[]
            # 查找到response['results'][i]['total_hits']个CVE
            for j in range(0, response['results'][i]['total_hits']):
                tmpCVEDict={}
                try:
                    if response['results'][i]['vulnerabilities'][j]['exploits']:
                        tmpCVEDict['CVEID']=response['results'][i]['vulnerabilities'][j]['cveid']
                        tmpCVEDict['CVEScore']=response['results'][i]['vulnerabilities'][j]['cvssv2_basescore']
                        cvssv2_basescore_sum += tmpCVEDict['CVEScore']
                        # tmpCVEDict['product']=response['results'][i]['query_string']
                        print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Exploit Found!")
                        print(bcolors.OKGREEN + "[>] " + bcolors.ENDC + "Product: " + productFilter(response['results'][i]['query_string']))
                        tmpEXPList=[]
                        # 一个CVE有几个POC
                        for z in range(0, len(response['results'][i]['vulnerabilities'][j]['exploits'])):
                            exploit_sum += 1
                            edb = response['results'][i]['vulnerabilities'][j]['exploits'][z]['url'].split("=")
                            tmpDictInList={}
                            tmpDictInList['desc']=response['results'][i]['vulnerabilities'][j]['exploits'][z]['title']
                            tmpDictInList['edb']="EDB"+edb[2]
                            tmpEXPList.append(tmpDictInList)
                            print(bcolors.OKGREEN + "[+] " + bcolors.ENDC + "Title: " + response['results'][i]['vulnerabilities'][j]['exploits'][z]['title'])
                            print(bcolors.FAIL + "[!] Exploit ID: EDB" + edb[2] + bcolors.ENDC + "\n")
                        tmpCVEDict['exp']=tmpEXPList
                        tmpCVEList.append(tmpCVEDict)
                except Exception as e:
                    continue

            if len(tmpCVEList) == 0:
                continue
            cveDictOfOneProduct['cve']=tmpCVEList
            cveDictOfOneProduct['product']=response['results'][i]['query_string']
            allProductExpList.append(cveDictOfOneProduct)
    else:
        pass
    print(allProductExpList)
    print("cvssv2_basescore_sum is:",cvssv2_basescore_sum)
    return allProductExpList

def vulnCheck(data=[],os="Linux",arc="x86_64"):
    # print("vulnCheck")
    count = 0
    # print("Reading software inventory from "+InventoryOutFile)
    # with open(InventoryOutFile) as json_file:
    # products = json.load(json_file)
    productExpList=[]
    if len(data) == 0:
        return productExpList
    # print("in")
    products = data
    # print(products)
    
    for a in products:
        if count == 0:
            queryData = '['
        queryData += '{'
        queryData += '"product": "' + a[0] + '",'
        queryData += '"version": "' + a[1] + '",'
        queryData += '"arc": "' + a[2] + '"'
        queryData += '},'
        count += 1
        #一次一百条
        if count == 100:
            count = 0
            tmpList=outResults(queryData,os=os,arc=arc)
            productExpList.extend(tmpList)
    tmpList=outResults(queryData,os=os,arc=arc)
    productExpList.extend(tmpList)
    # productExpListStr=json.dumps(productExpList)
    print(productExpList)
    print("+++++++++++++++++++++++++++++++++++Over++++++++++++++++++++++++++++++++++")
    return productExpList

def productFilter(productName):
    productName = productName.replace('\\"', "")
    return(productName)

def calculateScore():
    global os_check_score
    global cvssv2_basescore_sum
    #分数越高，严重性越高
    print("The final score of Linux baseline check is", os_check_score + cvssv2_basescore_sum )
    return os_check_score + cvssv2_basescore_sum 

#==========================================================================
# CLASS
#==========================================================================
class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    HEADER = '\033[95m'
class args:
    proxy = None
    proxytype = "http"

#==========================================================================
# MAIN PROGRAM
#==========================================================================
if __name__ == '__main__':
    with open('linux_res.json', 'r') as file:
        json_str = file.read()
    # 解析 JSON 字符串为 Python 字典对象
    data = json.loads(json_str)
    getProductList()
    linux_scan_res_report(data)
    calculateScore()