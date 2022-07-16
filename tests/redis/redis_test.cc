#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
 
#include <hiredis/hiredis.h>

#define CHECK(X) if ( !X || X->type == REDIS_REPLY_ERROR ) { printf("Error\n"); exit(-1); }

 
int main()
{
        // redisContext *redis_c;
        redisContext* _connect;
        redisReply* _reply;

        std::string auth_password = "Hestia123456";
        std::string host_ip = "127.0.0.1";
        _connect = redisConnect(host_ip.c_str(), 6379);
        if(_connect != NULL && _connect->err)
        {
            printf("connect error: %s\n", _connect->errstr);
        }
        redisCommand(_connect, "AUTH %s", auth_password.c_str());

        std::string key = "name";
        std::string value= "Andy";
        redisCommand(_connect, "SET %s %s", key.c_str(), value.c_str());

        _reply = (redisReply*)redisCommand(_connect, "GET %s", key.c_str());
        std::string str = _reply->str;
        freeReplyObject(_reply);

        std::cerr << "str: " << str << std::endl;

        return 0;
        

        // redisReply *reply;
        
        
        // char *s3 = "AUTH Hestia123456"; 
        // // char *p = auth_password.c_str();  //const不能省去！
        // reply = (redisReply *)redisCommand(redis_c, s3);
        // std::cout << reply << std::endl;

        // reply = (redisReply *)redisCommand(redis_c, "PING");
        // std::cout << reply << std::endl;
        
        // std::string temp = "SET foo bar";
        // redisAppendCommand(redis_c, temp.c_str());
        // redisAppendCommand(redis_c,"GET foo");
        // // if(redisGetReply(redis_c, (void **)&reply) == REDIS_OK
        // //         && reply != NULL
        // //         && reply->type == REDIS_REPLY_STRING)
        // // {
        // //         std::cerr << "reply->str: " << reply->str << std::endl;
        // //         // status = true;
        // //         // resp_str = reply->str;
        // // }
        // int r = redisGetReply(redis_c, (void **) &reply);
        // if (r == REDIS_ERR) {
        //         printf("ERROR1\n");
        // }
        // CHECK(reply);
        // printf("res: %s\n", reply->str);
        // freeReplyObject(reply);
        
        // freeReplyObject(reply);
        // std::cout << redisGetReply(redis_c,(void **)&reply); // GET命令的返回
        // // std::cout << reply->type << " " << REDIS_REPLY_STRING << std::endl;
        // freeReplyObject(reply);

        return 0;
}