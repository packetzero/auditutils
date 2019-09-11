#include <gtest/gtest.h>
#include <string>
#include <auditutils/auditrec_parser.hpp>

#include "example_records.hpp"
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

extern std::vector<ExampleRec> ex1_records;

const ExampleRec rec1 = {1300, "audit(1566400380.354:266): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7fdf339232a0 a2=6e a3=ffffffb4 items=1 ppid=115255 pid=97970 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"sshd\" exe=\"/usr/sbin/sshd\" key=(null)"};
const ExampleRec recArgs1 = {1309, "audit(1568215491.636:81166): argc=20 a0=\"/usr/lib/firefox/firefox\" a1=\"-contentproc\" a2=\"-childID\" a3=\"3\" a4=\"-isForBrowser\" a5=\"-prefsLen\" a6=\"7059\" a7=\"-prefMapSize\" a8=\"182813\" a9=\"-parentBuildID\" a10=\"20190718161435\" a11=\"-greomni\" a12=\"/usr/lib/firefox/omni.ja\" a13=\"-appomni\" a14=\"/usr/lib/firefox/brow ser/omni.ja\" a15=\"-appdir\" a16=\"/usr/lib/firefox/browser\" a17=\"69789\" a18=\"true\" a19=\"tab\""};

class AuditRecParseTests : public ::testing::Test {
protected:
  virtual void SetUp() override {
    listener_ = std::make_shared<MyAuditListener>();
  }
  virtual void TearDown() override {
    listener_->cleanup();
  }
  std::shared_ptr<MyAuditListener> listener_;
};

TEST_F(AuditRecParseTests, collect1) {

  auto spCollector = AuditCollectorNew(listener_);

  audit_reply reply;
  FILL_REPLY(reply, rec1);

  spCollector->onAuditRecord(reply);

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1300, spGroup->getType());
  EXPECT_EQ("266", spGroup->getSerial());
  EXPECT_EQ(1566400380, spGroup->getTimeSeconds());
  EXPECT_EQ(354, spGroup->getTimeMs());

  auto spRec = spGroup->getMessage(0);

  EXPECT_EQ(nullptr, spGroup->getMessage(-1));
  EXPECT_EQ(nullptr, spGroup->getMessage(2));
  EXPECT_EQ(1300, spRec->getType());
}

TEST_F(AuditRecParseTests, get_field) {

  auto spCollector = AuditCollectorNew(listener_);

  audit_reply reply;
  FILL_REPLY(reply, rec1);
  
  spCollector->onAuditRecord(reply);

  ASSERT_TRUE(listener_->vec.empty());

  spCollector->flush();

  ASSERT_EQ(1, listener_->vec.size());

  auto spGroup = listener_->vec[0];

  std::string pidstr;
  spGroup->getField("pid", pidstr, "X");
  ASSERT_EQ("97970",pidstr);
}

TEST_F(AuditRecParseTests, multi_groups) {

  auto spCollector = AuditCollectorNew(listener_);

  audit_reply reply;

  for (int i=0; i < 9; i++) {
    FILL_REPLY(reply, ex1_records[i]);
    
    spCollector->onAuditRecord(reply);

    if (i == 4) {
      ASSERT_EQ(1, listener_->vec.size());
    } else if (i == 8) {
      ASSERT_EQ(2, listener_->vec.size());
    }
  }

  auto spGroup = listener_->vec[0];

  std::string pidstr;
  spGroup->getField("syscall", pidstr, "X",1300);
  ASSERT_EQ("42",pidstr);

  std::string saddrstr;
  spGroup->getField("saddr", saddrstr, "X", 1306);
  ASSERT_EQ("020000357F000035F850DDC51F560000",saddrstr);

  std::string value;
  spGroup->getField("exe", value, "X",1300);
  ASSERT_EQ("/usr/sbin/NetworkManager", value);
}

TEST_F(AuditRecParseTests, concatSimple) {
  
  auto spCollector = AuditCollectorNew(listener_);
  
  audit_reply reply;
  FILL_REPLY(reply, recArgs1);
  
  spCollector->onAuditRecord(reply);
  
  spCollector->flush();
  
  ASSERT_EQ(1, listener_->vec.size());
  
  auto spGroup = listener_->vec[0];
  
  ASSERT_EQ(1,spGroup->getNumMessages());
  EXPECT_EQ(1309, spGroup->getType());

  std::string cmdline = spGroup->concatValues(1309,1);
  EXPECT_EQ("/usr/lib/firefox/firefox -contentproc -childID 3 -isForBrowser -prefsLen 7059 -prefMapSize 182813 -parentBuildID 20190718161435 -greomni /usr/lib/firefox/omni.ja -appomni \"/usr/lib/firefox/brow ser/omni.ja\" -appdir /usr/lib/firefox/browser 69789 true tab", cmdline);

  cmdline = spGroup->concatValues(222);
  EXPECT_EQ("",cmdline);
  
  cmdline = spGroup->concatValues(1309,-99);
  EXPECT_EQ("",cmdline);

  cmdline = spGroup->concatValues(1309,20);
  EXPECT_EQ("tab",cmdline);

  cmdline = spGroup->concatValues(1309,18);
  EXPECT_EQ("69789 true tab",cmdline);

  cmdline = spGroup->concatValues(1309,18, '_');
  EXPECT_EQ("69789_true_tab",cmdline);
}

