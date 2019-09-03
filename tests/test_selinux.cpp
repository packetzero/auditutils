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

//static ExampleRec ex_sel_avc_denied1 = {1400, "audit(1242575005.122:101): avc: denied { rename } for pid=2508 comm="canberra-gtk-pl" ...

TEST_F(AuditRecSELinuxParseTests, avc_denied1) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_avc_denied1);

  // avc: denied { rename } for pid=2508 comm="canberra-gtk-pl"

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1400, spGroup->getType());

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

TEST_F(AuditRecSELinuxParseTests, avc_record_granted) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_avc_granted1);

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1400, spGroup->getType());

  std::string value;
  EXPECT_TRUE(spGroup->getField(1400, "_avc_status", value, "X"));
  EXPECT_EQ("granted", value);
  EXPECT_TRUE(spGroup->getField(1400, "_avc_op", value, "X"));
  EXPECT_EQ("transition", value);
  EXPECT_TRUE(spGroup->getField(1400, "pid", value, "X"));
  EXPECT_EQ("7687", value);
}

// static ExampleRec ex_sel_policy1 = {1403,"audit(1336662937.117:394): policy loaded auid=0 ses=2"};
TEST_F(AuditRecSELinuxParseTests, sel_policy1) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_policy1);

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1403, spGroup->getType());

  std::string value;
  EXPECT_TRUE(spGroup->getField(0, "_policy_status", value, "X"));
  EXPECT_EQ("loaded", value);
  EXPECT_TRUE(spGroup->getField(0, "auid", value, "X"));
  EXPECT_EQ("0", value);
}

//static ExampleRec ex_sel_user_avc1 = {1167, "audit(1267534395.930:19): user pid=1169 uid=0 auid=4294967295 ses=4294967295 subj=system_u:unconfined_r:unconfined_t msg='avc: denied { read } for request=SELinux:SELinuxGetClientContext comm=X-setest resid=3c00001 restype=<unknown> scontext=unconfined_u:unconfined_r:x_select_paste_t tcontext=unconfined_u:unconfined_r:unconfined_t tclass=x_resource : exe=\"/usr/bin/Xorg\" sauid=0 hostname=? addr=? terminal=?'"};

TEST_F(AuditRecSELinuxParseTests, sel_user_avc1) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_user_avc1);

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1167, spGroup->getType());

  std::string value;
  EXPECT_TRUE(spGroup->getField(0, "_sel_prefix", value, "X"));
  EXPECT_EQ("user", value);
  EXPECT_TRUE(spGroup->getField(0, "pid", value, "X"));
  EXPECT_EQ("1169", value);
}

// static ExampleRec ex_sel_netlabel1 = {1416,"audit(1336664587.640:413): netlabel: auid=0 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 netif=lo src=127.0.0.1 sec_obj=system_u:object_r:unconfined_t:s0-s0:c0,c100 res=1"};

TEST_F(AuditRecSELinuxParseTests, sel_netlabel1) {

  auto spCollector = AuditCollectorNew(listener_);

  auto spReply = spCollector->allocReply();
  FILL_REPLY(spReply, ex_sel_netlabel1);

  spCollector->onAuditRecord(spReply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1416, spGroup->getType());

  std::string value;
  EXPECT_TRUE(spGroup->getField(0, "_sel_prefix", value, "X"));
  EXPECT_EQ("netlabel:", value);
  EXPECT_TRUE(spGroup->getField(0, "auid", value, "X"));
  EXPECT_EQ("0", value);
}
