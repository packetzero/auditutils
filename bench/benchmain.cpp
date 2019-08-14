#include <auditutils.hpp>
#include <sstream>
#include <oldauditutils.hpp>


static const std::string saddr_socket = "01002F7661722F72756E2F6E7363642F736F636B65740000EFC1DE857B7F0000070000000000000090F0FE857B7F00000100000000000000000000000000000001000000000000000025FF857B7F0000B03779857B7F00002074EF65010000000074EF65FC7F00001074EF65FC7F";

// IPV4 port:53 addr:
static const std::string saddrv4b = "0200001612CD5D010000000000000000";
static const std::string saddr2 = "020000357F000035C09CEE847B7F0000";

static const std::string saddrv6a = "0A000016000000002406DA00FF0000000000000034CCEA4A00000000";

static const std::string saddr_netlink = "100000000000000000000000";

static const std::string saddr_zero = "00000000000000000000000000000000";

void run(size_t loopCount) {

  size_t addrlen = 0;
  std::vector<std::string> saddrs = { saddrv4b, saddrv6a, saddr_zero, saddr_netlink, saddr2, saddr_socket};
  SockAddrInfo info;
  for (size_t i = 0; i < loopCount; i++) {
    for (auto saddr : saddrs) {
      info = SockAddrInfo();
      bool success = AuditParseUtils::parseSockAddr(saddr.c_str(), saddr.size(), info);
      if (success) {

        if (info.family == AuditParseUtils::FAM_IPV4) {
          auto addrstr = AuditParseUtils::ip4FromSaddr(info.addr4);
          addrlen += addrstr.size(); // do something so addrstr doesn't get optimized out
        }

        if (info.family != AuditParseUtils::FAM_UNIXSOCKET) {
          auto portstr = std::to_string(info.port);
          addrlen += portstr.size();
        }
      }

    }
  }
}

void runOld(size_t loopCount) {
  
  std::vector<std::string> saddrs = { saddrv4b, saddrv6a, saddr_zero, saddr_netlink, saddr2, saddr_socket};
  std::map<std::string,std::string> row;
  for (size_t i = 0; i < loopCount; i++) {
    for (auto saddr : saddrs) {
      row.clear();
      /*bool success =*/ OldAuditParser::parseSockAddr(saddr, row);
    }
  }
}


int main(int argc, char *argv[])
{
  bool useOld = false;
  if (argc == 2) {
    useOld = true;
  }

  size_t loopCount = 500000;
  if (useOld) {
    runOld(loopCount);
  } else {
    run(loopCount);
  }

}
