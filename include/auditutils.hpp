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
  static void _initLut(uint8_t *lut) {
    for (int i=0; i < 256; i++) { lut[i] = (uint8_t)0; }
    for (auto i='0'; i <= '9'; i++) { lut[(int)i] = (uint8_t)(i - '0'); }
    for (auto i='A'; i <= 'F'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'A');}
    for (auto i='a'; i <= 'f'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'a');}
  }

  static inline uint8_t charValue(const char c) {
    static uint8_t lut[256];
    static bool isInitialized=false;
    if (!isInitialized) {
      isInitialized = true;
      _initLut(lut);
    }
    return lut[(uint8_t)c];
  }
  static uint8_t parseU8(const char *str) {
    return charValue(str[0]) << 4 | charValue(str[1]);
  }
  static uint16_t parseU16(const char *str) {
    uint16_t value = charValue(str[0]) << 12 | charValue(str[1]) << 8;
    value |= charValue(str[2]) << 4 | charValue(str[3]);
    return value;
  }
  static uint32_t parseU32(const char *str) {
    uint32_t val = 0;
    val |= charValue(*str++) << 28;
    val |= charValue(*str++) << 24;
    val |= charValue(*str++) << 20;
    val |= charValue(*str++) << 16;
    val |= charValue(*str++) << 12;
    val |= charValue(*str++) << 8;
    val |= charValue(*str++) << 4;
    val |= charValue(*str++);
    return val;
  }

  //static const int FAM_IPV4 = 2;

  static bool parseSockAddr(const char *saddr, size_t len, SockAddrInfo &dest) {

    dest.family = parseU8(saddr);

    switch (dest.family) {
      case 2 : { // IPV4

        if (len < 16) {
          return false;
        }
        dest.port = parseU16(saddr + 4);
        dest.addr4 = parseU32(saddr + 8);
      }
      break;

      case 0x0A: { // IPv6
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
      case 1: { // unix socket

        if (len <= 6) {
          return false;
        }

        off_t begin = (saddr[4] == '0' && saddr[5] == '0') ? 6 : 4;
        auto end = strstr(saddr + begin, "00");
        end = (end == NULL) ? saddr + len : end;// + 4;
        dest.socketid = std::string(saddr + begin, end);// - begin);

      }
      break;
      default:
        return false;
    }
    return true;
  }

  static std::string ip4FromSaddr(uint32_t addr) {
    char tmp[32];
    snprintf(tmp,sizeof(tmp), "%d.%d.%d.%d", (addr >> 24)& 0x00FF, (addr >> 16)& 0x00FF, (addr >> 8) & 0x00FF, addr & 0x00FF);
    return std::string(tmp);
  }
};


/**
1300, audit(1565708882.149:189): arch=c000003e syscall=42 success=no exit=-2 a0=3 a1=7ffc65ef7370 a2=6e a3=6 items=1 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.149:189): saddr=01002F7661722F72756E2F6E7363642F736F636B65740000EFC1DE857B7F0000070000000000000090F0FE857B7F00000100000000000000000000000000000001000000000000000025FF857B7F0000B03779857B7F00002074EF65010000000074EF65FC7F00001074EF65FC7F
1307, audit(1565708882.149:189): cwd="/home/devo/dev/av-agent-build-linux/work/osquery"
1302, audit(1565708882.149:189): item=0 name="/var/run/nscd/socket" nametype=UNKNOWN cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
1327, audit(1565708882.149:189): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.149:189):
1300, audit(1565708882.149:190): arch=c000003e syscall=42 success=no exit=-2 a0=3 a1=7ffc65ef74e0 a2=6e a3=6 items=1 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.149:190): saddr=01002F7661722F72756E2F6E7363642F736F636B6574000000000000000000003000000000000000324389857B7F000070289FAD88550000801F0000FFFF00000000000000000000007D7F9B614D26605075EF65FC7F0000844C89857B7F000018CEFE857B7F000018CEFE857B7F
1307, audit(1565708882.149:190): cwd="/home/devo/dev/av-agent-build-linux/work/osquery"
1302, audit(1565708882.149:190): item=0 name="/var/run/nscd/socket" nametype=UNKNOWN cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
1327, audit(1565708882.149:190): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.149:190):
1300, audit(1565708882.149:191): arch=c000003e syscall=42 success=no exit=-2 a0=3 a1=7ffc65ef6cd0 a2=6e a3=6 items=1 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.149:191): saddr=01002F7661722F72756E2F6E7363642F736F636B657400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
1307, audit(1565708882.149:191): cwd="/home/devo/dev/av-agent-build-linux/work/osquery"
1302, audit(1565708882.149:191): item=0 name="/var/run/nscd/socket" nametype=UNKNOWN cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
1327, audit(1565708882.149:191): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.149:191):
1300, audit(1565708882.149:192): arch=c000003e syscall=42 success=no exit=-2 a0=3 a1=7ffc65ef6e60 a2=6e a3=6 items=1 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.149:192): saddr=01002F7661722F72756E2F6E7363642F736F636B657400001074EF65FC7F0000A05FEE847B7F0000AA99B5847B7F00009739B70100000000000000007B7F0000CB4FCB847B7F0000000000007B7F000000000000000000000100000000000000FFFFFFFFFFFFFFFF000000000300
1307, audit(1565708882.149:192): cwd="/home/devo/dev/av-agent-build-linux/work/osquery"
1302, audit(1565708882.149:192): item=0 name="/var/run/nscd/socket" nametype=UNKNOWN cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
1327, audit(1565708882.149:192): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.149:192):
1300, audit(1565708882.149:193): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7f7b84eedbd4 a2=10 a3=10 items=0 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.149:193): saddr=020000357F000035C09CEE847B7F0000
1327, audit(1565708882.149:193): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.149:193):
1300, audit(1565708882.185:194): arch=c000003e syscall=49 success=yes exit=0 a0=3 a1=7ffc65ef6f88 a2=c a3=0 items=0 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.185:194): saddr=100000000000000000000000
1327, audit(1565708882.185:194): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.185:194):
1300, audit(1565708882.185:195): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=5588ad9f5f20 a2=10 a3=4 items=0 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.185:195): saddr=0200001612CD5D010000000000000000
1327, audit(1565708882.185:195): proctitle=2F7573722F62696E2F73736800676974406269746275636B65742E6F7267006769742D75706C6F61642D7061636B2027616C69656E61646D696E2F61762D6167656E742D6F7371756572792E67697427
1320, audit(1565708882.185:195):
1300, audit(1565708882.189:196): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffc65ef73c0 a2=10 a3=4 items=0 ppid=95930 pid=95931 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts1 ses=3 comm="ssh" exe="/usr/bin/ssh" key=(null)
1306, audit(1565708882.189:196): saddr=00000000000000000000000000000000
*/
