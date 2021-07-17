/*
 * ngtcp2
 *
 * Copyright (c) 2019 ngtcp2 contributors
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
#include "shared.h"

#include <nghttp3/nghttp3.h>

#include <cstring>
#include <cassert>
#include <iostream>

#include <unistd.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#ifdef HAVE_ASM_TYPES_H
#  include <asm/types.h>
#endif // HAVE_ASM_TYPES_H
#ifdef HAVE_LINUX_NETLINK_H
#  include <linux/netlink.h>
#endif // HAVE_LINUX_NETLINK_H
#ifdef HAVE_LINUX_RTNETLINK_H
#  include <linux/rtnetlink.h>
#endif // HAVE_LINUX_RTNETLINK_H

#include "template.h"

namespace ngtcp2 {

QUICError quic_err_transport(int liberr) {
  if (liberr == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
    return {QUICErrorType::TransportVersionNegotiation, 0};
  }
  return {QUICErrorType::Transport,
          ngtcp2_err_infer_quic_transport_error_code(liberr)};
}

QUICError quic_err_idle_timeout() {
  return {QUICErrorType::TransportIdleTimeout, 0};
}

QUICError quic_err_tls(int alert) {
  return {QUICErrorType::Transport,
          static_cast<uint64_t>(NGTCP2_CRYPTO_ERROR | alert)};
}

QUICError quic_err_app(int liberr) {
  return {QUICErrorType::Application,
          nghttp3_err_infer_quic_app_error_code(liberr)};
}

unsigned int msghdr_get_ecn(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
          cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg));
      }
    }
    break;
  }

  return 0;
}

void fd_set_ecn(int fd, int family, unsigned int ecn) {
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_TOS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &ecn,
                   static_cast<socklen_t>(sizeof(ecn))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

void fd_set_recv_ecn(int fd, int family) {
  unsigned int tos = 1;
  switch (family) {
  case AF_INET:
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  case AF_INET6:
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &tos,
                   static_cast<socklen_t>(sizeof(tos))) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
    }
    break;
  }
}

std::optional<Address> msghdr_get_local_addr(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cmsg));
        Address res{};
        res.ifindex = pktinfo->ipi_ifindex;
        res.len = sizeof(res.su.in);
        auto &sa = res.su.in;
        sa.sin_family = AF_INET;
        sa.sin_addr = pktinfo->ipi_addr;
        return res;
      }
    }
    return {};
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
        Address res{};
        res.ifindex = pktinfo->ipi6_ifindex;
        res.len = sizeof(res.su.in6);
        auto &sa = res.su.in6;
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = pktinfo->ipi6_addr;
        return res;
      }
    }
    return {};
  }
  return {};
}

void set_port(Address &dst, Address &src) {
  switch (dst.su.storage.ss_family) {
  case AF_INET:
    assert(AF_INET == src.su.storage.ss_family);
    dst.su.in.sin_port = src.su.in.sin_port;
    return;
  case AF_INET6:
    assert(AF_INET6 == src.su.storage.ss_family);
    dst.su.in6.sin6_port = src.su.in6.sin6_port;
    return;
  default:
    assert(0);
  }
}

#ifdef HAVE_LINUX_RTNETLINK_H

struct nlmsg {
  nlmsghdr hdr;
  rtmsg msg;
  rtattr dst;
  in_addr_union dst_addr;
};

namespace {
int send_netlink_msg(int fd, const Address &remote_addr) {
  nlmsg nlmsg{};
  nlmsg.hdr.nlmsg_type = RTM_GETROUTE;
  nlmsg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

  nlmsg.msg.rtm_family = remote_addr.su.sa.sa_family;

  nlmsg.dst.rta_type = RTA_DST;

  switch (remote_addr.su.sa.sa_family) {
  case AF_INET:
    nlmsg.dst.rta_len = RTA_LENGTH(sizeof(remote_addr.su.in.sin_addr));
    memcpy(RTA_DATA(&nlmsg.dst), &remote_addr.su.in.sin_addr,
           sizeof(remote_addr.su.in.sin_addr));
    break;
  case AF_INET6:
    nlmsg.dst.rta_len = RTA_LENGTH(sizeof(remote_addr.su.in6.sin6_addr));
    memcpy(RTA_DATA(&nlmsg.dst), &remote_addr.su.in6.sin6_addr,
           sizeof(remote_addr.su.in6.sin6_addr));
    break;
  default:
    assert(0);
  }

  nlmsg.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(nlmsg.msg) + nlmsg.dst.rta_len);

  sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;

  iovec iov{&nlmsg, nlmsg.hdr.nlmsg_len};
  msghdr msg{};
  msg.msg_name = &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t nwrite;

  do {
    nwrite = sendmsg(fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    std::cerr << "sendmsg: Could not write netlink message: " << strerror(errno)
              << std::endl;
    return -1;
  }

  return 0;
}
} // namespace

namespace {
int recv_netlink_msg(in_addr_union &iau, int fd) {
  std::array<uint8_t, 8192> buf;
  iovec iov = {buf.data(), buf.size()};
  sockaddr_nl sa{};
  msghdr msg{};

  msg.msg_name = &sa;
  msg.msg_namelen = sizeof(sa);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t nread;

  do {
    nread = recvmsg(fd, &msg, 0);
  } while (nread == -1 && errno == EINTR);

  if (nread == -1) {
    std::cerr << "recvmsg: Could not receive netlink message: "
              << strerror(errno) << std::endl;
    return -1;
  }

  for (auto hdr = reinterpret_cast<nlmsghdr *>(buf.data());
       NLMSG_OK(hdr, nread); hdr = NLMSG_NEXT(hdr, nread)) {
    switch (hdr->nlmsg_type) {
    case NLMSG_DONE:
      std::cerr << "netlink: no info returned from kernel" << std::endl;
      return -1;
    case NLMSG_NOOP:
      continue;
    case NLMSG_ERROR:
      std::cerr << "netlink: "
                << strerror(-static_cast<nlmsgerr *>(NLMSG_DATA(hdr))->error)
                << std::endl;
      return -1;
    }

    auto attrlen = hdr->nlmsg_len - NLMSG_SPACE(sizeof(rtmsg));

    for (auto rta = reinterpret_cast<rtattr *>(
             static_cast<uint8_t *>(NLMSG_DATA(hdr)) + sizeof(rtmsg));
         RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
      if (rta->rta_type != RTA_PREFSRC) {
        continue;
      }

      size_t in_addrlen;

      switch (static_cast<rtmsg *>(NLMSG_DATA(hdr))->rtm_family) {
      case AF_INET:
        in_addrlen = sizeof(in_addr);
        break;
      case AF_INET6:
        in_addrlen = sizeof(in6_addr);
        break;
      default:
        assert(0);
      }

      if (RTA_LENGTH(in_addrlen) != rta->rta_len) {
        return -1;
      }

      memcpy(&iau, RTA_DATA(rta), in_addrlen);

      return 0;
    }
  }

  return -1;
}
} // namespace

int get_local_addr(in_addr_union &iau, const Address &remote_addr) {
  sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;

  auto fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd == -1) {
    std::cerr << "socket: Could not create netlink socket: " << strerror(errno)
              << std::endl;
    return -1;
  }

  auto fd_d = defer(close, fd);

  if (bind(fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == -1) {
    std::cerr << "bind: Could not bind netlink socket: " << strerror(errno)
              << std::endl;
    return -1;
  }

  if (send_netlink_msg(fd, remote_addr) != 0) {
    return -1;
  }

  return recv_netlink_msg(iau, fd);
}

#endif // HAVE_LINUX_NETLINK_H

bool addreq(const sockaddr *sa, const in_addr_union &iau) {
  switch (sa->sa_family) {
  case AF_INET:
    return memcmp(&reinterpret_cast<const sockaddr_in *>(sa)->sin_addr, &iau.in,
                  sizeof(iau.in)) == 0;
  case AF_INET6:
    return memcmp(&reinterpret_cast<const sockaddr_in6 *>(sa)->sin6_addr,
                  &iau.in6, sizeof(iau.in6)) == 0;
  default:
    assert(0);
  }
}

} // namespace ngtcp2
