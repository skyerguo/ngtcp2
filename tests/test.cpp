#include <iostream>
#include <string>
#include <cstring>
#include <algorithm>

std::string getStdLocation(std::string dc) {
  /* 对应bash python3 -c "import os; print('-'.join([''.join((t[:2], t[-2:])) for t in '${dc}'.split('-')[:2]])) */
  std::string res = "";
  std::string pre[2] = {"", ""};
  int fx[4] = {-1, 0, 0, 1};
  int n = dc.size();
  int cnt = 0, last_pos = 0;
  for (int i = 0; i < n; ++i) {
    if (dc[i] == '-') {
      pre[cnt] = dc.substr(last_pos, i - last_pos);
      last_pos = i + 1;
      if (++cnt > 1) break;
     }
  }
  std::cout << pre[0] << std::endl;
  std::cout << pre[1] << std::endl;
  res = pre[0].substr(0, 2) + pre[0].substr(pre[0].size() - 2, pre[0].size()) + "-";
  res += pre[1].substr(0, 2) + pre[1].substr(pre[1].size() - 2, pre[0].size());
  return res;
}

int main() {
    std::cout << getStdLocation("us-west2-c") << std::endl;
    std::cout << getStdLocation("europe-west1-c") << std::endl;
    return 0;
}