#include <gtest/gtest.h>
#include <string>
#include <auditutils/auditrec_parser.hpp>

#include "example_selinux_records.hpp"
//audit(1105758604.519:420): avc: denied { getattr } for pid=5962 comm="httpd" path="/home/auser/public_html" dev=sdb2 ino=921135

struct MyAuditListener : public AuditListener {
  virtual ~MyAuditListener() {}
  bool onAuditRecords(SPAuditGroup spRecordGroup) override {
    vec.push_back(spRecordGroup);
    return false;
  }
  void cleanup() {
    for (auto spRecGroup : vec) {
      spRecGroup->release();
    }
    vec.clear();
  }
  std::vector<SPAuditGroup> vec;
};



class AuditRecSELinuxParseTests : public ::testing::Test {
public:
  AuditRecSELinuxParseTests() : ::testing::Test() {
    auto selParser = SELinuxFieldsParserNew();

    AuditRecParsers::getInstance().addFieldsParser(selParser);
  }
protected:
  virtual void SetUp() override {
    listener_ = std::make_shared<MyAuditListener>();
  }
  virtual void TearDown() override {
    listener_->cleanup();
  }
  std::shared_ptr<MyAuditListener> listener_;
};

static inline void FILL_REPLY(SPAuditRecBuf spRecBuf, const ExampleRec &rec) {
  auto spReply = std::static_pointer_cast<AuditReplyBuf>(spRecBuf);
  strcpy(spReply->data(), rec.msg.data());
  spReply->len = rec.msg.size();
  spReply->type = rec.rectype;
}

TEST_F(AuditRecSELinuxParseTests, collect1) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_records1[0]);

  // avc: denied { rename } for pid=2508 comm="canberra-gtk-pl"

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1400, spGroup->getType());

  //int recType, const std::string &name, std::string &dest, std::string defaultValue
  std::string value;
  EXPECT_TRUE(spGroup->getField(1400, "_avc_status", value, "X"));
  EXPECT_EQ("denied", value);
  EXPECT_TRUE(spGroup->getField(1400, "_avc_op", value, "X"));
  EXPECT_EQ("rename", value);
  EXPECT_TRUE(spGroup->getField(1400, "pid", value, "X"));
  EXPECT_EQ("2508", value);
  EXPECT_TRUE(spGroup->getField(1400, "comm", value, "X"));
  EXPECT_EQ("canberra-gtk-pl", value);
}
