#pragma once

#include <stdint.h>
#include <string>
#include "hexi.hpp"

struct SockAddrInfo {
  uint32_t port;
  uint32_t addr4;
  uint8_t family;
  std::string addr6;
  std::string socketid;
};

struct AuditParseUtils {

  static const int FAM_IPV4 = 2;
  static const int FAM_IPV6 = 0xA;
  static const int FAM_UNIXSOCKET = 1;

  /*
   * Parse audit netlink saddr
   */
  static bool parseSockAddr(const char *saddr, size_t len, SockAddrInfo &dest) {

    if (len <= 4) {
      return false;
    }

    dest.family = Hexi::parseU8(saddr);

    switch (dest.family) {
      case FAM_IPV4 : {

        if (len < 16) {
          return false;
        }
        dest.port = Hexi::parseU16(saddr + 4);
        dest.addr4 = Hexi::parseU32(saddr + 8);
      }
      break;

      case FAM_IPV6: {
        if (len < (16 + 32)) {
          return false;
        }
        dest.port = Hexi::parseU16(saddr + 4);
        char tmp[48];
        char *p = tmp;
        const char *src = saddr + 16;
        for (size_t i = 0; i < 8; ++i) {
          *p++ = tolower(*src++);
          *p++ = tolower(*src++);
          *p++ = tolower(*src++);
          *p++ = tolower(*src++);
          if (i == 0 || i % 7 != 0) {
            *p++ = ':';
          }
        }
        *p = 0;
        dest.addr6 = std::string(tmp);
      }
      break;

      case FAM_UNIXSOCKET: {

        if (len <= 6) {
          return false;
        }

        off_t begin = (saddr[4] == '0' && saddr[5] == '0') ? 6 : 4;
        auto end = strstr(saddr + begin, "00");
        end = (end == NULL) ? saddr + len : end;
        dest.socketid = std::string(saddr + begin, end);

      }
      break;
      default:
        return false;
    }
    return true;
  }

  /*
   * Can't use inet_ntoa or inet_ptoa, since addr is not network endian
   */
  static std::string ip4FromSaddr(uint32_t addr) {
    char tmp[32];
    snprintf(tmp,sizeof(tmp), "%d.%d.%d.%d", (addr >> 24)& 0x00FF, (addr >> 16)& 0x00FF, (addr >> 8) & 0x00FF, addr & 0x00FF);
    return std::string(tmp);
  }

  /// concatenate the value strings for fields in message of type
  /// skip can be used to skip over a number of fields at beginning
  static std::string extractCommandline(const char *body, size_t bodylen) {
    int nth = 0;
    int skip = 1;

    auto dst = std::vector<uint8_t>(bodylen);
    uint8_t *pdest = dst.data();

    const char *start = body;
    const char *pend = body + bodylen;

    while (start < pend) {
      const char *p = start ;
      while (p != pend && *p != '=') {
        p++;
      }
      if (p == pend) {
        break;
      }
      //const char *keyEnd = p;
      p++;
      if (p == pend) {
        break;
      }
      const char *valueStart = p;
      bool isQuoted = false;
      char endChar = ' ';
      if (*p == '"' || *p == '\'') {
        isQuoted = true;
        endChar = *p;
        p++;
        valueStart = p;
      }
      if (nth > 1) {
        *pdest++ = ' ';
      }

      // find end of value
      if (nth == 0) {
        // skip over argc="n"
        p++;
      } else {
        if (!isQuoted) {
          // this is hex-encoded because it contains a space
          *pdest++ = '"';
          // first find end
          const char *valstart = p;
          while (p < pend && (*p != endChar)) {
            p++;
          }
          size_t valLen = p-valstart;
          if (Hexi::hex2ascii((char *)pdest, valLen, valstart, valLen)) {
            // failed
          } else {
            pdest+= valLen / 2; // each 2-char hex is 1 char
          }

          *pdest++ = '"';
        } else {
          // just copy over contents of string value
          while (p < pend && (*p != endChar)) {
            *pdest++ = *p++;
          }
        }
      }

      // advance
      nth++;
      start = p + (isQuoted ? 2 : 1);
    }
    auto dstlen = pdest - dst.data();
    return std::string((char*)dst.data(), dstlen);
  }


};
