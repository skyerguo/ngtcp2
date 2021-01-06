#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <cstdio>

using namespace std;

int main() {
    // system("ls");
    string s = "redis-cli -h 10.142.0.4 -a 'Hestia123456' set foo bar";
    s = "ls";
    system(s); 
    return 0;
}
