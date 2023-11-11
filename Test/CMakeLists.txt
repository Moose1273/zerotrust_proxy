# CMake版本
cmake_minimum_required(VERSION 3.18.0)

# `std::make_unique`要求最低C++17
set(CMAKE_CXX_STANDARD 17)

# 工程名
project(SDP_Proxy)

####################################### 添加线程库 #######################################
find_package(Threads REQUIRED)
##########################################################################################

####################################### 添加libhtp库 #######################################
if ("$ENV{LIBHTP_ROOT}" STREQUAL "") # 自动查找
    find_path(LIBHTP_INCLUDE_DIR NAMES htp.h)
else () # 如果有手动配置LIBHTP环境变量LIBHTP_ROOT, 则从环境变量中获取
    set(LIBHTP_INCLUDE_DIR $ENV{LIBHTP_ROOT}/include/htp)
endif ()
find_library(LIBHTP_LIBRARIES NAMES htp HINTS ${LIBHTP_INCLUDE_DIR}/../../lib)
set(LIBHTP_ROOT_DIR ${LIBHTP_INCLUDE_DIR}/../../)
message(STATUS "libhtp root dir: ${LIBHTP_ROOT_DIR}")
message(STATUS "libhtp include path: ${LIBHTP_INCLUDE_DIR}")
message(STATUS "libhtp libraries: ${LIBHTP_LIBRARIES}")
if ("${LIBHTP_ROOT_DIR}" STREQUAL "LIBHTP_ROOT_DIR-NOTFOUND" OR
    "${LIBHTP_INCLUDE_DIR}" STREQUAL "LIBHTP_INCLUDE_DIR-NOTFOUND" OR
    "${LIBHTP_LIBRARIES}" STREQUAL "LIBHTP_LIBRARIES-NOTFOUND")
    message(WARNING "libhtp not found")
    return()
else ()
    include_directories(${LIBHTP_INCLUDE_DIR})
endif ()
##########################################################################################

# 循环添加目录下的依赖
function(get_cxx_files SEARCH_PATH SOURCE_LIST)
    set(SOURCE_EXP *.h *.hpp *.c *.cc *.cpp)
    set(SOURCE_EXP_WITH_PATH)
    foreach(EXP ${SOURCE_EXP})
        list(APPEND SOURCE_EXP_WITH_PATH ${SEARCH_PATH}/${EXP})
    endforeach()
    file(GLOB FILES ${SOURCE_EXP_WITH_PATH})
    set(${SOURCE_LIST} ${FILES} PARENT_SCOPE)
endfunction()


# 添加宏定义
add_definitions(-DHAVE_CONFIG_H=1)
add_definitions(-DLOCAL_STATE_DIR="/home/hb/SDP_Proxy")

# 添加头文件包含目录
include_directories(/usr/include/nss)
include_directories(/usr/include/nspr)
include_directories(suricata/suricata/src)
include_directories(suricata/suricata/rust/dist)

# 添加suricata源文件
set(proc_files)
get_cxx_files(suricata/suricata/src src_list)
list(APPEND proc_files ${src_list})
list(REMOVE_ITEM proc_files ${CMAKE_CURRENT_SOURCE_DIR}/suricata/suricata/src/main.c) # 这里去除源码中的主文件

# 添加主进程源文件
get_cxx_files(src src_list)
list(APPEND proc_files ${src_list})

message("proc_files files:")
foreach(filename ${proc_files})
    message("    " ${filename})
endforeach()

# 构建可执行文件
add_executable(SDP_Proxy ${proc_files})

find_package(OpenSSL REQUIRED)

# 链接依赖库文件
target_link_libraries(SDP_Proxy Threads::Threads
                                     OpenSSL::Crypto OpenSSL::SSL
                                     ${LIBHTP_LIBRARIES}
                                     pcap
                                     dl
                                     rt
                                     m
                                     #lz4
                                     magic
                                     cap-ng
                                     jansson
                                     yaml
                                     z
                                     pcre
                                     pcre2-8
                                     ssl3
                                     smime3
                                     nss3
                                     nssutil3
                                     net
                                     plds4
                                     plc4
                                     nspr4
                                     netfilter_queue
                                     mnl
                                     nfnetlink
                                     
                                     /home/hb/Test/suricata/suricata/rust/target/release/libsuricata.a)

