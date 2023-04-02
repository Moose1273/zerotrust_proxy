// #include "infoAnalyzer.h"

// int infoAnalyzer::analyzeInfo(char *buffer)
// {
//     cJSON *root = cJSON_Parse(buffer);
//     if (!root)
//     {
//         std::cerr << "Parse SPA packet failed!" << std::endl;
//         cJSON_Delete(root);
//         return 0;
//     }
//     cJSON *item = nullptr;
//     char *action_str = nullptr;
//     item = cJSON_GetObjectItem(root, "action");
//     if (item != nullptr)
//     {
//         // 判断是不是字符串类型
//         if (item->type == cJSON_String)
//         {
//             // 通过函数获取值
//             action_str = cJSON_Print(item);
//             cout << "this is action_str: " << action_str << endl;
//             if (strcmp(action_str, "\"spa_response\"") == 0)
//             {
//                 // 做处理
//                 char *status_str = nullptr;
//                 cJSON *idx = cJSON_GetObjectItem(root, "status");
//                 status_str = cJSON_Print(idx);
//                 cout << "this is status_str: " << status_str << endl;
//                 if (strcmp(status_str, "\"200\"") == 0)
//                 {
//                     // todo:200之后要干什么
//                     std::cout << "controller accept connection" << std::endl;
//                 }
//                 else if (strcmp(status_str, "\"300\"") == 0)
//                 {
//                     std::cout << "controller refuse connection" << std::endl;
//                     free(status_str);
//                     free(action_str);
//                     return 0;
//                 }
//                 else
//                 {
//                     // todo 其他状态码
//                     free(status_str);
//                     free(action_str);
//                     return 0;
//                 }
//                 free(status_str);
//             }
//             else if (strcmp(action_str, "\"login_response\"") == 0)
//             {
//                 // 做处理
//                 char *status_str = nullptr;
//                 cJSON *idx = cJSON_GetObjectItem(root, "status");
//                 status_str = cJSON_Print(idx);
//                 cout << "this is status_str: " << status_str << endl;
//                 if (strcmp(status_str, "\"200\"") == 0)
//                 {
//                     // todo:200之后要干什么
//                     std::cout << "controller accept login" << std::endl;
//                 }
//                 else if (strcmp(status_str, "\"300\"") == 0)
//                 {
//                     std::cout << "controller refuse login" << std::endl;
//                     free(status_str);
//                     free(action_str);
//                     return 0;
//                 }
//                 else
//                 {
//                     // todo 其他状态码
//                     free(status_str);
//                     free(action_str);
//                     return 0;
//                 }
//                 free(status_str);
//             }
//             //服务请求响应
//             //从响应包中提取信息，构造SPA包发送给网关
//             else if (strcmp(action_str, "\"service_response\"") == 0)
//             {
//                 // 做处理
//                 char *status_str = nullptr;
//                 cJSON *data_idx = cJSON_GetObjectItem(root, "data");
//                 cJSON *service_list_idx = cJSON_GetObjectItem(data_idx, "serviceList");
//                 if (!service_list_idx)
//                 {
//                     printf("Get service_list_idx error -1");
//                     return 0;
//                 }
//                 // 获取数组长度
//                 auto len = cJSON_GetArraySize(service_list_idx);
//                 vector<pair<string, int>> serverIDS;
//                 unordered_set<string> serverIdMap;
//                 for (auto i = 0; i < len; ++i) // 对每个数组元素进行处理
//                 {
//                     cJSON *obj = cJSON_GetArrayItem(service_list_idx, i); // 获取的数组里的obj
//                     cJSON *serverId = NULL;
//                     cJSON *val = NULL;
//                     if (obj != NULL && obj->type == cJSON_Object)
//                     {                                                    // 判断数字内的元素是不是obj类型
//                         serverId = cJSON_GetObjectItem(obj, "serverId"); // 获得obj里的值

//                         if (serverId != NULL && serverId->type == cJSON_String)
//                         {
//                             status_str = serverId->valuestring;
//                             // printf("serverId = %s\n", status_str);
//                             cout << "serverId = " << status_str << endl;
//                             serverIdMap.insert(status_str);
//                             serverIDS.push_back({status_str, i});
//                         }
//                         else
//                         {
//                             cerr << "get serverId failed!" << endl;
//                         }
//                     }
//                 }
//                 // user select a service
//                 cout << "plz select a serviceId or q for quit" << endl;
//                 string serv;
//                 while (1)
//                 {
//                     cin >> serv;
//                     if (serv.compare("q") == 0)
//                     {
//                         break;
//                     }
//                     // find service
//                     else if (serverIdMap.find(serv) != serverIdMap.end())
//                     {
//                         char *gatewayIP = nullptr;
//                         char *gatewayPort = nullptr;
//                         char *hotp = nullptr;
//                         char *hmac = nullptr;
//                         // do something
//                         cout << "do something" << endl;
//                         int idx = -1;
//                         for (auto iter : serverIDS)
//                         {
//                             if (iter.first == serv)
//                             {
//                                 cJSON *obj = cJSON_GetArrayItem(service_list_idx, iter.second);
//                                 if (obj != nullptr && obj->type == cJSON_Object)
//                                 {
//                                     cJSON *IP = cJSON_GetObjectItem(obj, "gatewayIP");
//                                     cJSON *PORT = cJSON_GetObjectItem(obj, "gatewayPort");
//                                     cJSON *HOTP = cJSON_GetObjectItem(data_idx, "hotp");
//                                     cJSON *HMAC = cJSON_GetObjectItem(data_idx, "hmac");
//                                     char *gatewayIP = IP->valuestring;
//                                     char *gatewayPort = PORT->valuestring;
//                                     char *hotp = HOTP->valuestring;
//                                     char *hmac = HMAC->valuestring;
//                                     cout << gatewayIP << " " << gatewayPort << " " <<atoi(gatewayPort)<<" "<< hotp << " " << hmac << endl;
//                                     //怎么传回呢？
                                    
//                                 }
//                             }
//                         }
//                         break;
//                     }
//                     cout << "plz input a serviceId or type q for quit" << endl;
//                 }
//             }
//             else
//             {
//                 /* code */
//                 // todo 其他action

//                 cout << "coming to else" << endl;
//             }
//         }
//         else
//         {
//             cout << "not a cJSON_String type" << endl;
//         }
//         // 通过函数返回的指针需要自行free，否则会导致内存泄漏
//         free(action_str);
//     }
//     cJSON_Delete(root);
//     return 1;
// }

// int infoAnalyzer::login_request(std::vector<char> &data)
// {
//     char buffer[1024];
//     cJSON *root = cJSON_CreateObject();
//     cJSON_AddItemToObject(root, "action", cJSON_CreateString("login_request"));
//     // 定义user data对象 { }
//     cJSON *user_data = cJSON_CreateObject();
//     cJSON_AddItemToObject(user_data, "userId", cJSON_CreateString("just a user"));
//     cJSON_AddItemToObject(user_data, "password", cJSON_CreateNumber(123457896453));
//     cJSON_AddItemToObject(root, "data", user_data);
//     char *cPrint = cJSON_Print(root);
//     memmove(buffer, cPrint, 1024);
//     cout << buffer << endl;
//     data.insert(data.end(), buffer, buffer + strlen(buffer));
//     return true;
// }