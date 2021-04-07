#ifndef _REDIS_H_
#define _REDIS_H_
 
#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
 
#include <hiredis/hiredis.h>
 
class Redis
{
public:
 
    Redis(){}
 
    ~Redis()
    {
        this->_connect = NULL;
        this->_reply = NULL;                
    }
 
    bool connect(std::string host, int port)
    {
        this->_connect = redisConnect(host.c_str(), port);
        if(this->_connect != NULL && this->_connect->err)
        {
            printf("connect error: %s\n", this->_connect->errstr);
            return 0;
        }
        return 1;
    }
 
    std::string get(std::string key)
    {
        this->_reply = (redisReply*)redisCommand(this->_connect, "GET %s", key.c_str());
        std::string str = this->_reply->str;
        freeReplyObject(this->_reply);
        return str;
    }
 
    void set(std::string key, std::string value)
    {
        redisCommand(this->_connect, "SET %s %s", key.c_str(), value.c_str());
    }

    void auth(std::string auth_password)
    {
	    redisCommand(this->_connect, "auth %s", auth_password.c_str());
    }

    int existsKey(const char* ID){
        redisReply * reply = (redisReply*)redisCommand(this->_connect,"exists %s",ID);
        int res = 0;
        if(reply->type == REDIS_REPLY_INTEGER){
            if(reply->integer == 1L)
                res  = 1;
        }
        freeReplyObject(reply);
        return res;
    }
 
private:
 
    redisContext* _connect;
    redisReply* _reply;
 
};
 
#endif
