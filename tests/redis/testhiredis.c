#include <stdio.h>
#include <hiredis/hiredis.h>

int main() {
    // Blocking redisContext
    redisContext *conn = redisConnect("127.0.0.1", 6379);
    if (conn != NULL && conn->err) {
        printf("connection error: %s\n", conn->errstr);
        return 0;
    }

    redisCommand(conn, "auth Hestia123456");

    // Use redisCommand to send commands and get returns
    redisReply *reply;
    reply = redisCommand(conn, "SET %s %s", "foo", "bar");
    freeReplyObject(reply);

    reply = redisCommand(conn, "GET %s", "foo");
    printf("%s\n", reply->str);
    freeReplyObject(reply);

    // Pipelining with redisAppendCommand
    redisAppendCommand(conn, "set a b");
    redisAppendCommand(conn, "get a");
    int r = redisGetReply(conn, (void **)&reply);
    if (r == REDIS_ERR) {
        printf("ERROR\n");
    }
    printf("res: %s\n", reply->str);
    freeReplyObject(reply);

    r = redisGetReply(conn, (void **)&reply);
    if (r == REDIS_ERR) {
        printf("ERROR\n");
    }
    printf("res: %s\n", reply->str);
    freeReplyObject(reply);

    // Use watch command to monitor key a
    reply = redisCommand(conn, "watch a");
    printf("watch res: %s\n", reply->str);
    freeReplyObject(reply);

    // Transaction pipeline, 5 commands in total
    redisAppendCommand(conn, "multi");
    redisAppendCommand(conn, "get foo");
    redisAppendCommand(conn, "set t tt");
    redisAppendCommand(conn, "set a aa");
    redisAppendCommand(conn, "exec");

    for (int i = 0; i < 5; ++i) {
        r = redisGetReply(conn, (void **)&reply);
        if (r == REDIS_ERR) {
            printf("ERROR\n");
        }
        printf("res: %s, num: %zu, type: %d\n", reply->str, reply->elements, reply->type);
        freeReplyObject(reply);
    }

    // Test the inconsistency between redisGetReply and redisAppendCommand calls
    redisAppendCommand(conn, "get t");
    // I wanted to get t he return of set a ddd, but I got the return of get
    reply = redisCommand(conn, "set a ddd");
    printf("set a res: %s\n", reply->str);

    redisFree(conn);

    return 0;
}
