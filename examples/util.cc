/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "util.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H

#include <chrono>
#include <array>

namespace ngtcp2 {

namespace util {

namespace {
constexpr char LOWER_XDIGITS[] = "0123456789abcdef";
} // namespace

std::string format_hex(uint8_t c) {
  std::string s;
  s.resize(2);

  s[0] = LOWER_XDIGITS[c >> 4];
  s[1] = LOWER_XDIGITS[c & 0xf];

  return s;
}

std::string format_hex(const uint8_t *s, size_t len) {
  std::string res;
  res.resize(len * 2);

  for (size_t i = 0; i < len; ++i) {
    auto c = s[i];

    res[i * 2] = LOWER_XDIGITS[c >> 4];
    res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

std::mt19937 make_mt19937() {
  std::random_device rd;
  return std::mt19937(rd());
}

ngtcp2_tstamp timestamp() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

bool numeric_host(const char *hostname) {
  return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
}

bool numeric_host(const char *hostname, int family) {
  int rv;
  std::array<uint8_t, sizeof(struct in6_addr)> dst;

  rv = inet_pton(family, hostname, dst.data());

  return rv == 1;
}

namespace {
void hexdump8(FILE *out, const uint8_t *first, const uint8_t *last) {
  auto stop = std::min(first + 8, last);
  for (auto k = first; k != stop; ++k) {
    fprintf(out, "%02x ", *k);
  }
  // each byte needs 3 spaces (2 hex value and space)
  for (; stop != first + 8; ++stop) {
    fputs("   ", out);
  }
  // we have extra space after 8 bytes
  fputc(' ', out);
}
} // namespace

void hexdump(FILE *out, const uint8_t *src, size_t len) {
  if (len == 0) {
    return;
  }
  size_t buflen = 0;
  auto repeated = false;
  std::array<uint8_t, 16> buf{};
  auto end = src + len;
  auto i = src;
  for (;;) {
    auto nextlen =
        std::min(static_cast<size_t>(16), static_cast<size_t>(end - i));
    if (nextlen == buflen &&
        std::equal(std::begin(buf), std::begin(buf) + buflen, i)) {
      // as long as adjacent 16 bytes block are the same, we just
      // print single '*'.
      if (!repeated) {
        repeated = true;
        fputs("*\n", out);
      }
      i += nextlen;
      continue;
    }
    repeated = false;
    fprintf(out, "%08lx", static_cast<unsigned long>(i - src));
    if (i == end) {
      fputc('\n', out);
      break;
    }
    fputs("  ", out);
    hexdump8(out, i, end);
    hexdump8(out, i + 8, std::max(i + 8, end));
    fputc('|', out);
    auto stop = std::min(i + 16, end);
    buflen = stop - i;
    auto p = buf.data();
    for (; i != stop; ++i) {
      *p++ = *i;
      if (0x20 <= *i && *i <= 0x7e) {
        fputc(*i, out);
      } else {
        fputc('.', out);
      }
    }
    fputs("|\n", out);
  }
}
double stringToDouble(std::string num)
{
    bool minus = false;      //标记是否是负数
    std::string real = num;       //real表示num的绝对值
    if (num.at(0) == '-')
    {
        minus = true;
        real = num.substr(1, num.size()-1);
    }

    char c;
    int i = 0;
    double result = 0.0 , dec = 10.0;
    bool isDec = false;       //标记是否有小数
    unsigned long size = real.size();
    while(i < size)
    {
        c = real.at(i);
        if (c == '.')
        {//包含小数
            isDec = true;
            i++;
            continue;
        }
        if (!isDec)
        {
            result = result*10 + c - '0';
        }
        else
        {//识别小数点之后都进入这个分支
            result = result + (c - '0')/dec;
            dec *= 10;
        }
        i++;
    }
    if (minus == true) {
        result = -result;
    }

    return result;
}

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
  // std::cout << pre[0] << std::endl;
  // std::cout << pre[1] << std::endl;
  res = pre[0].substr(0, 2) + pre[0].substr(pre[0].size() - 2, pre[0].size()) + "-";
  res += pre[1].substr(0, 2) + pre[1].substr(pre[1].size() - 2, pre[0].size());
  return res;
}

uint64_t address2Int(const std::string &ip) {
  uint64_t res = 0;
  uint64_t last = 0;
  int n = ip.size();
  for (int i = 0; i < n; ++i) {
    if (ip[i] == '.') {
      res = res * 1000 + last;
      last = 0;
    }
    else {
      last = last * 10 + ip[i] - '0';
    }
  }
  res = res * 1000 + last;
  return res;
}

std::string int2Address(uint64_t ip_int) {
  std::string res = "";
  for (int i = 0; ip_int > 0; ++i) {
    res = std::to_string(ip_int % 10) + res;
    ip_int /= 10;
    if (i % 3 == 0) res = "." + res;
  }
  return res;
}

std::string getUinque(const uint64_t &a, const uint64_t &b, const uint64_t &c) {
  std::string res = "";
  res = std::to_string(a) + '_';
  res += std::to_string(b) + '_';
  res += std::to_string(c);
  return res;
}

std::string getUniqueLogFile(const uint64_t &a, const uint64_t &b, const uint64_t &c) {
  std::string res = "/home/gtc/experiemnt_results/";
  res += getUinque(a, b, c);
  res += ".txt";
  return res;
}
} // namespace util

} // namespace ngtcp2
