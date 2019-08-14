#pragma once

#include <stdint.h>
#include <string>

struct SockAddrInfo {
  uint32_t port;
  uint32_t addr4;
  uint8_t family;
  std::string addr6;
  std::string socketid;
};

struct AuditParseUtils {

  /*
   * Parse 2-char hex to byte.
   * Caller must ensure str has length.
   */
  static uint8_t parseU8(const char *str) {
    return CVAL(str[0]) << 4 | CVAL(str[1]);
  }

  /*
   * Parse 4-char hex to unsigned short 16-bit.
   * Caller must ensure str has length.
   */
  static uint16_t parseU16(const char *str) {
    uint16_t value = CVAL(str[0]) << 12 | CVAL(str[1]) << 8;
    value |= CVAL(str[2]) << 4 | CVAL(str[3]);
    return value;
  }

  /*
   * Parse 8-char hex to unsigned 32-bit int.
   * Caller must ensure str has length.
   */
  static uint32_t parseU32(const char *str) {
    uint32_t val = 0;
    val |= CVAL(*str++) << 28;
    val |= CVAL(*str++) << 24;
    val |= CVAL(*str++) << 20;
    val |= CVAL(*str++) << 16;
    val |= CVAL(*str++) << 12;
    val |= CVAL(*str++) << 8;
    val |= CVAL(*str++) << 4;
    val |= CVAL(*str++);
    return val;
  }

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

    dest.family = parseU8(saddr);

    switch (dest.family) {
      case FAM_IPV4 : {

        if (len < 16) {
          return false;
        }
        dest.port = parseU16(saddr + 4);
        dest.addr4 = parseU32(saddr + 8);
      }
      break;

      case FAM_IPV6: {
        if (len < (16 + 32)) {
          return false;
        }
        dest.port = parseU16(saddr + 4);
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

protected:
  static bool _initLut(uint8_t *lut) {
    for (int i=0; i < 256; i++) { lut[i] = (uint8_t)0; }
    for (auto i='0'; i <= '9'; i++) { lut[(int)i] = (uint8_t)(i - '0'); }
    for (auto i='A'; i <= 'F'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'A');}
    for (auto i='a'; i <= 'f'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'a');}
    return true;
  }
  static uint8_t* _lut() {
    static uint8_t lut[256];
    static bool isInitialized=_initLut(lut);
    return lut;
  }
  static inline uint8_t CVAL(const char c) {
    return _lut()[(uint8_t)c];
  }

};
