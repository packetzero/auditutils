#include <gtest/gtest.h>
#include <string>
#include <auditutils/auditutils.hpp>
#include <auditutils/_x_oldauditutils.hpp>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status= RUN_ALL_TESTS();
  return status;
}

class AuditParseTests : public ::testing::Test {
protected:
  virtual void SetUp() override {
  }
  virtual void TearDown() override {
  }
};

static const std::string saddr_socket = "01002F7661722F72756E2F6E7363642F736F636B65740000EFC1DE857B7F0000070000000000000090F0FE857B7F00000100000000000000000000000000000001000000000000000025FF857B7F0000B03779857B7F00002074EF65010000000074EF65FC7F00001074EF65FC7F";

// IPV4 port:53 addr:
static const std::string saddrv4b = "0200001612CD5D010000000000000000";
static const std::string saddr2 = "020000357F000035C09CEE847B7F0000";

static const std::string saddrv6a = "0A000016000000002406DA00FF0000000000000034CCEA4A00000000";

static const std::string saddr_netlink = "100000000000000000000000";

static const std::string saddr_zero = "00000000000000000000000000000000";

TEST_F(AuditParseTests, uno) {

  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddr2.c_str(), saddr2.size(), info);
  ASSERT_TRUE(success);
  ASSERT_EQ(2, info.family);
  ASSERT_EQ(0x0035, info.port);
  ASSERT_EQ(0x7F000035, info.addr4);
  auto addrstr = AuditParseUtils::ip4FromSaddr(info.addr4);
  ASSERT_EQ("127.0.0.53", addrstr);
}

TEST_F(AuditParseTests, netlink_ignore) {

  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddr_netlink.c_str(), saddr_netlink.size(), info);
  ASSERT_FALSE(success);
}

TEST_F(AuditParseTests, zero_ignore) {

  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddr_zero.c_str(), saddr_zero.size(), info);
  ASSERT_FALSE(success);
}


TEST_F(AuditParseTests, old_uno) {

  std::map<std::string,std::string> row;
  row["action"] = "connect";
  bool success = OldAuditParser::parseSockAddr(saddr2, row);
  ASSERT_TRUE(success);
  ASSERT_EQ("2", row["family"]);
  ASSERT_EQ("53", row["remote_port"]);
  ASSERT_EQ("127.0.0.53", row["remote_address"]);
}

TEST_F(AuditParseTests, old_v4b) {

  std::map<std::string,std::string> row;
  row["action"] = "connect";
  bool success = OldAuditParser::parseSockAddr(saddrv4b, row);
  ASSERT_TRUE(success);
  ASSERT_EQ("2", row["family"]);
  ASSERT_EQ("22", row["remote_port"]);
  ASSERT_EQ("18.205.93.1", row["remote_address"]);
}

TEST_F(AuditParseTests, v4b) {


  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddrv4b.c_str(), saddrv4b.size(), info);
  ASSERT_TRUE(success);
  ASSERT_EQ(2, info.family);
  ASSERT_EQ(22, info.port);
  auto addrstr = AuditParseUtils::ip4FromSaddr(info.addr4);
  ASSERT_EQ("18.205.93.1", addrstr);

}

TEST_F(AuditParseTests, v4b_partial) {

  SockAddrInfo info = SockAddrInfo();
  bool success = AuditParseUtils::parseSockAddr(saddrv4b.c_str(), 13 /* too short */, info);
  ASSERT_FALSE(success);
  ASSERT_EQ(2, info.family);
  ASSERT_EQ(0, info.port);
  ASSERT_EQ(0, info.addr4);
}

TEST_F(AuditParseTests, v6a) {


  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddrv6a.c_str(), saddrv6a.size(), info);
  ASSERT_TRUE(success);
  ASSERT_EQ(10, info.family);
  ASSERT_EQ(22, info.port);
  ASSERT_EQ("2406:da00:ff00:0000:0000:0000:34cc:ea4a", info.addr6);

}

TEST_F(AuditParseTests, v6a_partial) {


  SockAddrInfo info = SockAddrInfo();
  bool success = AuditParseUtils::parseSockAddr(saddrv6a.c_str(), 22 /* too short */, info);
  ASSERT_FALSE(success);
  ASSERT_EQ(10, info.family);
  ASSERT_EQ(0, info.port);
  ASSERT_EQ("", info.addr6);
}


TEST_F(AuditParseTests, old_v6a) {

  std::map<std::string,std::string> row;
  row["action"] = "connect";
  bool success = OldAuditParser::parseSockAddr(saddrv6a, row);
  ASSERT_TRUE(success);
  ASSERT_EQ("10", row["family"]);
  ASSERT_EQ("22", row["remote_port"]);
  ASSERT_EQ("2406:da00:ff00:0000:0000:0000:34cc:ea4a", row["remote_address"]);
}

TEST_F(AuditParseTests, socket1) {


  SockAddrInfo info;
  bool success = AuditParseUtils::parseSockAddr(saddr_socket.c_str(), saddr_socket.size(), info);
  ASSERT_TRUE(success);
  ASSERT_EQ("2F7661722F72756E2F6E7363642F736F636B6574", info.socketid);

}

TEST_F(AuditParseTests, old_socket1) {

  std::map<std::string,std::string> row;
  row["action"] = "connect";
  bool success = OldAuditParser::parseSockAddr(saddr_socket, row);
  ASSERT_TRUE(success);
  ASSERT_EQ("1", row["family"]);
  ASSERT_EQ("2F7661722F72756E2F6E7363642F736F636B6574", row["socket"]);
}

TEST_F(AuditParseTests, hex2ascii) {
  const std::string s = "2F746D702F746865206C73";
  std::string dest;
  Hexi::hex2ascii(dest, s);
  EXPECT_EQ("/tmp/the ls", dest);
}

static std::string cmdlineEx1 = "argc=20 a0=\"/usr/lib/firefox/firefox\" a1=\"-contentproc\" a2=\"-childID\" a3=\"3\" a4=\"-isForBrowser\" a5=\"-prefsLen\" a6=\"7059\" a7=\"-prefMapSize\" a8=\"182813\" a9=\"-parentBuildID\" a10=\"20190718161435\" a11=\"-greomni\" a12=\"/usr/lib/firefox/omni.ja\" a13=\"-appomni\" a14=2F746D702F746865206C73 a15=\"-appdir\" a16=\"/usr/lib/firefox/browser\" a17=\"69789\" a18=\"true\" a19=\"tab\"";

TEST_F(AuditParseTests, cmdline1) {
  std::string cmdline = AuditParseUtils::extractCommandline(cmdlineEx1.data(), cmdlineEx1.size());
  EXPECT_EQ("/usr/lib/firefox/firefox -contentproc -childID 3 -isForBrowser -prefsLen 7059 -prefMapSize 182813 -parentBuildID 20190718161435 -greomni /usr/lib/firefox/omni.ja -appomni \"/tmp/the ls\" -appdir /usr/lib/firefox/browser 69789 true tab", cmdline);
}

TEST_F(AuditParseTests, cmdline2) {
  std::string rec = "argc=3 a0=2F746D702F746865206C73 a1=2F746D702F746865206C73 a2=";
  std::string cmdline = AuditParseUtils::extractCommandline(rec.data(), rec.size());
  EXPECT_EQ("\"/tmp/the ls\" \"/tmp/the ls\"", cmdline);

  // two hex-encoded args that are invalid (length not multiple of 2)
  rec = "argc=3 a0=2F7 a1=2";
  cmdline = AuditParseUtils::extractCommandline(rec.data(), rec.size());
  EXPECT_EQ("\"\" \"\"", cmdline);
}
