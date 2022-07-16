#include <iostream>
#include <vector>
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <string>

void foo(std::vector<std::string> & pipeLineCmd) {
    for (int i = 0; i < 5; ++i)
    {
        std::string a = std::to_string(i);
        pipeLineCmd[i] = "get latency_" + a;
    }
}

int main() {
    std::vector<std::string> pipeLineCmd;
    
    for (int i = 0; i < 5; ++i)
    {
        std::string a = std::to_string(i);
        pipeLineCmd.push_back("get cpu_" + a);
    }
    foo(pipeLineCmd);
    for (int i = 0; i < 5; ++i) {
        std::cout << pipeLineCmd[i] << std::endl;
    }
    return 0;
}