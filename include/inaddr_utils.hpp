#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct InetAddrUtils {
  static std::string ip4FromSaddr(uint32_t addr) {
    struct in_addr a = {addr};
    char *tmp = inet_ntoa(a);
    return std::string(tmp);
  }
};
