#include "ngtcp2_redis_test.h"
 
int main()
{
    Redis *r = new Redis();
    if(!r->connect("127.0.0.1", 6379))
    {
        printf("connect error!\n");
        return 0;
    }
    r->set("name", "Andy");
    printf("Get the name is %s\n", r->get("name").c_str());
    delete r;
    return 0;
}