#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <vector>
 
#include <hiredis/hiredis.h>

#define CHECK(X) if ( !X || X->type == REDIS_REPLY_ERROR ) { printf("Error\n"); exit(-1); }

void pipeLineRedisCmdGet(redisContext* rc, std::vector<std::string> & pipeLineCmd, std::vector<std::string> &pipeLineReq, std::vector<bool> &pipeLineReqStatus)
{
    for(int i = 0; i < pipeLineCmd.size(); i++)
    {
      redisAppendCommand(rc, "GET %s", pipeLineCmd[i].c_str());
    }
    for (int i = 0; i < pipeLineCmd.size(); i++)
    {
        bool status = false;
        std::string resp_str = "";
        redisReply *reply = 0;
        if(redisGetReply(rc, (void **)&reply) == REDIS_OK
                && reply != NULL
                && reply->type == REDIS_REPLY_STRING)
        {
            status = true;
            resp_str = reply->str;
        }
        //free
        freeReplyObject(reply);
        pipeLineReqStatus.push_back(status);
        pipeLineReq.push_back(resp_str);
    }
}

 
int main()
{
    std::vector<std::string> pipeLineCmd;
    std::vector<std::string> pipeLineReq;
    std::vector<bool> pipeLineReqStatus;
    for (int i = 0; i < 5; ++i)
    {
        std::string a = "s" + std::to_string(i);
        pipeLineCmd.push_back("cpu_" + a);
    }
    // pipeLineRedisCmd(redis_c, pipeLineCmd, pipeLineReq, pipeLineReqStatus);
    for (int i = 0; i < pipeLineCmd.size(); ++i)
        std::cerr << "i: " << i << " pipeLineCmd: " << pipeLineCmd[i] << std::endl;

    redisContext* redis_c;
    redisReply* reply;
    std::string auth_password = "Hestia123456";
    // std::cerr << "config.redis_ip: " << config.redis_ip << std::endl;
    const char* redis_host_ip = "127.0.0.1";

    redis_c = redisConnect(redis_host_ip, 6379);
    if (redis_c != NULL && redis_c->err) 
    {
        std::cerr << "connect error: " <<  redis_c->errstr << std::endl;
    }
    else
    {
        std::cerr << "redis_c connection success" << std::endl;
                std::cerr << "redis_c connection success" << std::endl;
        // redisReply *reply = (redisReply *)redisCommand(redis_c, "AUTH %s", "Hestia123456");
        // std::cerr << "!!!!!" << std::endl;
        // std::cerr << "reply->type: " << reply->type << std::endl;
        reply = (redisReply*)redisCommand(redis_c, "AUTH %s", auth_password.c_str());
        if (reply == NULL || reply->type == REDIS_REPLY_ERROR)
            std::cerr << "Redis认证失败！"<< std::endl;
        else
            std::cerr << "Redis认证成功！"<< std::endl;
        freeReplyObject(reply);
    }
    // redisContext* redis_c;
    // redisReply* reply;

    // std::string auth_password = "Hestia123456";
    // const char* redis_host_ip = "198.22.255.15";
    // redis_c = redisConnect(redis_host_ip, 6379);

    // if(redis_c != NULL && redis_c->err)
    // {
    //     printf("connect error: %s\n", redis_c->errstr);
    // }
    // reply = (redisReply*)redisCommand(redis_c, "AUTH %s", auth_password.c_str());
    // if (reply == NULL || reply->type == REDIS_REPLY_ERROR)
    //     std::cerr << "Redis认证失败！"<< std::endl;
    // else
    //     std::cerr << "Redis认证成功！"<< std::endl;
    // freeReplyObject(reply);
    
    // for (int i = 0; i < pipeLineCmd.size(); ++i) {
    //     reply = (redisReply*)redisCommand(redis_c, "GET %s", pipeLineCmd[i].c_str());
    //     std::string str = reply->str;
    //     freeReplyObject(reply);
    //     std::cerr << "str: " << str << std::endl;
    // }

    // for (int i = 0; i < pipeLineCmd.size(); ++i)
    //     std::cerr << "i: " << i << " pipeLineCmd: " << pipeLineCmd[i] << std::endl;
    // pipeLineRedisCmdGet(redis_c, pipeLineCmd, pipeLineReq, pipeLineReqStatus);
    // for (int i = 0; i < pipeLineCmd.size(); ++i)
    //     std::cerr << "i: " << i << " pipeLineCmd: " << pipeLineCmd[i] << " pipeLineReq: " << pipeLineReq[i] << " pipeLineReqStatus: " << pipeLineReqStatus[i] << std::endl;
        
    redisFree(redis_c);

    return 0;
}

// 编译方式：g++ pipelineredis.cc -opt -lhiredis