#include <gtest/gtest.h>
#include <string>
#include <auditrec_parser.hpp>

#include "example_records.hpp"
//audit(1105758604.519:420): avc: denied { getattr } for pid=5962 comm="httpd" path="/home/auser/public_html" dev=sdb2 ino=921135


extern std::vector<ExampleRec> ex1_records;

const ExampleRec rec1 = {1300, "audit(1566400380.354:266): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7fdf339232a0 a2=6e a3=ffffffb4 items=1 ppid=115255 pid=97970 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"sshd\" exe=\"/usr/sbin/sshd\" key=(null)"};

class AuditRecParseTests : public ::testing::Test {
protected:
  virtual void SetUp() override {
  }
  virtual void TearDown() override {
  }
};

TEST_F(AuditRecParseTests, typical) {
  SPAuditRecParser spParser = AuditRecParserNew();
  spParser->parse(rec1.rectype, rec1.msg.data(), rec1.msg.size());
}
