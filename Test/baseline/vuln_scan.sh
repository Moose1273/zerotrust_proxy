#!/bin/bash
function vulnScan() {
	os=$(uname -s)
	arc=$(uname -i)
	local softList=()
	kernel_info=$(cat /proc/version)
	if echo "$kernel_info" | grep -qiE 'debian|ubuntu'; then
  		echo "当前使用的是 Debian 内核"
		osname=$(lsb_release -a | grep "Description:" | awk -F"\t" '{print $2}')
		while read row; do
		softList+=($row)
		done < <(dpkg-query -W -f='${Package}\n${Version}\n')
	# 判断内核信息中是否包含 "red hat" 或 "centos" 字符串，用于判断是否为 RHEL 内核
	elif echo "$kernel_info" | grep -qiE 'red hat|centos'; then
		echo "当前使用的是 RHEL 内核"
		osname=$(cat "/etc/redhat-release")
		while read row; do
		softList+=($row)
		done < <(rpm -qai|grep -E '^(Version[[:space:]]+:|Name[[:space:]]+:)'|sed -e 's/[[:space:]]\{1,\}/ /g'|cut -d' ' -f3)
	else
  		echo "无法确定当前使用的内核"
	fi
	# rpm->centos系统
	#done < <(rpm -qai|grep -E '^(Version[[:space:]]+:|Name[[:space:]]+:)'|sed -e 's/[[:space:]]\{1,\}/ /g'|cut -d' ' -f3)
	
	# dpkg->ubuntu系统
	#done < <(dpkg-query -W -f='${Package}\n${Version} \n')
	#done < <(dpkg-query -W -f='${Package}\n${Version}\n')
	#vulnScanList="["
	#centos系统
	#osname=$(cat "/etc/redhat-release")
	
	#ubuntu系统
	#osname=$(lsb_release -a | grep "Description:" | awk -F"\t" '{print $2}')
	
	vulnScanList="["
	for ((i=0;i<${#softList[@]};i=$i+2)); do
		if [[ $i == 0 ]]; then
			tmpScan="[\"${softList[$i]}\",\"${softList[(($i+1))]}\",\"$osname\"]"
		else
			tmpScan=",[\"${softList[$i]}\",\"${softList[(($i+1))]}\",\"$osname\"]"
		fi
		vulnScanList+="$tmpScan"
	done
	vulnScanList+="]"
	vulnScanResult={\"os\":\"$os\",\"arc\":\"$arc\",\"vulnScanList\":$vulnScanList}
	echo "==========================vulnScanResult======================"
	echo $vulnScanResult 
#	echo $vulnScanResult|jq
}
