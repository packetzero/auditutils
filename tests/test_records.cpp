#include <gtest/gtest.h>
#include <string>
#include <auditrec_parser.hpp>

#include "example_records.hpp"
//audit(1105758604.519:420): avc: denied { getattr } for pid=5962 comm="httpd" path="/home/auser/public_html" dev=sdb2 ino=921135

struct MyAuditListener : public AuditListener {
  bool onAuditRecords(SPAuditGroup spRecordGroup) override {
    vec.push_back(spRecordGroup);
    return false;
  }
  void cleanup(SPAuditCollector spCollector) {
    for (auto spRecGroup : vec) {
      spCollector->releaseRecords(spRecGroup);
    }
    vec.clear();
  }
  std::vector<SPAuditGroup> vec;
};

extern std::vector<ExampleRec> ex1_records;

const ExampleRec rec1 = {1300, "audit(1566400380.354:266): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7fdf339232a0 a2=6e a3=ffffffb4 items=1 ppid=115255 pid=97970 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"sshd\" exe=\"/usr/sbin/sshd\" key=(null)"};

class AuditRecParseTests : public ::testing::Test {
protected:
  virtual void SetUp() override {
    listener_ = std::make_shared<MyAuditListener>();
  }
  virtual void TearDown() override {
  }
  std::shared_ptr<MyAuditListener> listener_;
};

TEST_F(AuditRecParseTests, typical) {
  SPAuditRecParser spParser = AuditRecParserNew();
  spParser->parse(rec1.rectype, rec1.msg.data(), rec1.msg.size());
}

static inline void FILL_REPLY(SPAuditReply spReply, const ExampleRec &rec) {
  strcpy(spReply->msg.data, rec.msg.data());
  spReply->len = rec.msg.size();
  spReply->type = rec.rectype;
}

TEST_F(AuditRecParseTests, collect1) {
  

  auto spCollector = AuditCollectorNew(listener_);
  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, rec1);
  
  spCollector->onAuditRecord(spReply);
  spCollector->flush();
}

