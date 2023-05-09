import json

# ==========================================================================
# GLOBAL VARIABLES
# ==========================================================================

#os安全配置
win_os_check_sum = 0
pass_Num = 0
win_os_check_score = 0

#软件漏洞
cvssv2_basescore_sum = 0

def windows_scan_res_report(windowsScanResDict={}):
    global win_os_check_score
    global pass_Num  
    global win_os_check_sum
    basic_info = windowsScanResDict['basic_info']
    account_check_res = windowsScanResDict['account_check_res']
    password_check_info = account_check_res['password_check_info']
    passwordHistorySize = password_check_info['passwordHistorySize']
    win_os_check_sum += 1
    if int(passwordHistorySize) >= 5:
        pass_Num += 1
    maximumPasswordAge = password_check_info['maximumPasswordAge']
    win_os_check_sum += 1
    if int(maximumPasswordAge) <= 90:
        pass_Num += 1
    minimumPasswordAge = password_check_info['minimumPasswordAge']
    win_os_check_sum += 1
    if int(minimumPasswordAge) >= 1:
        pass_Num += 1
    passwordComplexity = password_check_info['passwordComplexity']
    win_os_check_sum += 1
    if int(passwordComplexity) == 1:
        pass_Num += 1
    clearTextPassword = password_check_info['clearTextPassword']
    win_os_check_sum += 1
    if int(clearTextPassword) == 1:
        pass_Num += 1
    minimumPasswordLength = password_check_info['minimumPasswordLength']
    win_os_check_sum += 1
    if int(minimumPasswordLength) >= 8:
        pass_Num += 1
    account_lockout_info = account_check_res['account_lockout_info']
    lockoutDuration = account_lockout_info['lockoutDuration']
    win_os_check_sum += 1
    if int(lockoutDuration) >= 15:
        pass_Num += 1
    lockoutBadCount = account_lockout_info['lockoutBadCount']
    win_os_check_sum += 1
    if int(lockoutBadCount) <= 5:
        pass_Num += 1
    resetLockoutCount = account_lockout_info['resetLockoutCount']
    win_os_check_sum += 1
    if int(resetLockoutCount) >= 15 and int(resetLockoutCount) <= int(lockoutDuration):
        pass_Num += 1
    audit_check_res = windowsScanResDict['audit_check_res']
    auditPolicyChange = audit_check_res['auditPolicyChange']
    win_os_check_sum += 1
    if int(auditPolicyChange) >= 1:
        pass_Num += 1
    auditLogonEvents = audit_check_res['auditLogonEvents']
    win_os_check_sum += 1
    if int(auditLogonEvents) == 3:
        pass_Num += 1
    auditObjectAccess = audit_check_res['auditObjectAccess']
    win_os_check_sum += 1
    if int(auditObjectAccess) >= 1:
        pass_Num += 1
    auditProcessTracking = audit_check_res['auditProcessTracking']
    win_os_check_sum += 1
    if int(auditProcessTracking) == 3:
        pass_Num += 1
    auditDSAccess = audit_check_res['auditDSAccess']
    win_os_check_sum += 1
    if int(auditDSAccess) == 3:
        pass_Num += 1
    auditSystemEvents = audit_check_res['auditSystemEvents']
    win_os_check_sum += 1
    if int(auditSystemEvents) == 3:
        pass_Num += 1
    auditAccountLogon = audit_check_res['auditAccountLogon']
    win_os_check_sum += 1
    if int(auditAccountLogon) == 3:
        pass_Num += 1
    auditAccountManage = audit_check_res['auditAccountManage']
    win_os_check_sum += 1
    if int(auditAccountManage) == 3:
        pass_Num += 1
    userright_check_res = windowsScanResDict['userright_check_res']
    seTrustedCredManAccessPrivilegeIFNone = userright_check_res[
        'seTrustedCredManAccessPrivilegeIFNone']
    win_os_check_sum += 1
    if seTrustedCredManAccessPrivilegeIFNone == "True":
        pass_Num += 1
    seTcbPrivilegeIFNone = userright_check_res['seTcbPrivilegeIFNone']
    win_os_check_sum += 1
    if seTcbPrivilegeIFNone == "True":
        pass_Num += 1
    seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray = userright_check_res[
        'seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray']
    win_os_check_sum += 1
    if seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray == "True":
        pass_Num += 1
    seCreateGlobalPrivilegeIFNone = userright_check_res['seCreateGlobalPrivilegeIFNone']
    win_os_check_sum += 1
    if seCreateGlobalPrivilegeIFNone == "True":
        pass_Num += 1
    seDenyBatchLogonRightIFContainGuests = userright_check_res[
        'seDenyBatchLogonRightIFContainGuests']
    win_os_check_sum += 1
    if seDenyBatchLogonRightIFContainGuests == "True":
        pass_Num += 1
    seDenyServiceLogonRightIFContainGuests = userright_check_res[
        'seDenyServiceLogonRightIFContainGuests']
    win_os_check_sum += 1
    if seDenyServiceLogonRightIFContainGuests == "True":
        pass_Num += 1
    seDenyInteractiveLogonRightIFContainGuests = userright_check_res[
        'seDenyInteractiveLogonRightIFContainGuests']
    win_os_check_sum += 1
    if seDenyInteractiveLogonRightIFContainGuests == "True":
        pass_Num += 1
    seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray = userright_check_res[
        'seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray']
    win_os_check_sum += 1
    if seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray == "True":
        pass_Num += 1
    seRelabelPrivilegeIFNone = userright_check_res['seRelabelPrivilegeIFNone']
    win_os_check_sum += 1
    if seRelabelPrivilegeIFNone == "True":
        pass_Num += 1
    seSyncAgentPrivilegeIFNone = userright_check_res['seSyncAgentPrivilegeIFNone']
    win_os_check_sum += 1
    if seSyncAgentPrivilegeIFNone == "True":
        pass_Num += 1
    secureoption_check_res = windowsScanResDict['secureoption_check_res']
    enableGuestAccount = secureoption_check_res['enableGuestAccount']
    win_os_check_sum += 1
    if enableGuestAccount == "True":
        pass_Num += 1
    limitBlankPasswordUse = secureoption_check_res['limitBlankPasswordUse']
    win_os_check_sum += 1
    if limitBlankPasswordUse == "True":
        pass_Num += 1
    newAdministratorName = secureoption_check_res['newAdministratorName']
    win_os_check_sum += 1
    if newAdministratorName == "True":
        pass_Num += 1
    newGuestName = secureoption_check_res['newGuestName']
    win_os_check_sum += 1
    if newGuestName == "True":
        pass_Num += 1
    dontDisplayLastUserName = secureoption_check_res['dontDisplayLastUserName']
    win_os_check_sum += 1
    if dontDisplayLastUserName == "True":
        pass_Num += 1
    disableCAD = secureoption_check_res['disableCAD']
    win_os_check_sum += 1
    if disableCAD == "True":
        pass_Num += 1
    inactivityTimeoutSecs = secureoption_check_res['inactivityTimeoutSecs']
    win_os_check_sum += 1
    if inactivityTimeoutSecs != "False" and int(inactivityTimeoutSecs) <= 900:
        pass_Num += 1
    enablePlainTextPassword = secureoption_check_res['enablePlainTextPassword']
    win_os_check_sum += 1
    if enablePlainTextPassword == "True":
        pass_Num += 1
    autoDisconnect = secureoption_check_res['autoDisconnect']
    win_os_check_sum += 1
    if autoDisconnect != "False" and int(autoDisconnect) >= 15:
        pass_Num += 1
    noLMHash = secureoption_check_res['noLMHash']
    win_os_check_sum += 1
    if noLMHash == "True":
        pass_Num += 1
    lsaAnonymousNameLookup = secureoption_check_res['lsaAnonymousNameLookup']
    win_os_check_sum += 1
    if lsaAnonymousNameLookup == "True":
        pass_Num += 1
    restrictAnonymousSAM = secureoption_check_res['restrictAnonymousSAM']
    win_os_check_sum += 1
    if restrictAnonymousSAM == "True":
        pass_Num += 1
    restrictAnonymous = secureoption_check_res['restrictAnonymous']
    win_os_check_sum += 1
    if restrictAnonymous == "True":
        pass_Num += 1
    clearPageFileAtShutdown = secureoption_check_res['clearPageFileAtShutdown']
    win_os_check_sum += 1
    if clearPageFileAtShutdown == "True":
        pass_Num += 1
    portsecure_check_res = windowsScanResDict['portsecure_check_res']
    rdpPort = portsecure_check_res['rdpPort']
    win_os_check_sum += 1
    if int(rdpPort) != 3389:
        pass_Num += 1
    systemsecure_check_res = windowsScanResDict['systemsecure_check_res']
    autoRunRes = systemsecure_check_res['autoRunRes']
    win_os_check_sum += 1
    if autoRunRes != "False" and int(autoRunRes) >= 233:
        pass_Num += 1
    win_os_check_score += (win_os_check_sum - pass_Num)/win_os_check_sum*100
    if 80 <= win_os_check_score and win_os_check_score <= 100:
        win_os_check_score = 4
    elif win_os_check_score <= 60:
        win_os_check_score = 3
    elif win_os_check_score <= 40:
        win_os_check_score = 2
    elif win_os_check_score <= 20:
        win_os_check_score = 1
    else: win_os_check_score = 0
    print("win baseline check score is: ",win_os_check_score)
    return win_os_check_score

def windows_inventory_scan_res_report(inventory_data={}):
    global cvssv2_basescore_sum 
    cvssv2_basescore_sum += inventory_data['cvssv2_basescore_sum']
    print("windows_inventory_check_score is: ", cvssv2_basescore_sum)
    return cvssv2_basescore_sum
