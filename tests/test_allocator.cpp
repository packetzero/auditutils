#include <gtest/gtest.h>
#include <string>
#include <auditutils/auditrec_parser.hpp>
#include "test_defs.h"

class AuditRecAllocatorTests : public ::testing::Test {
protected:
  virtual void SetUp() override {
  }
  virtual void TearDown() override {
  }
};

const ExampleRec rec1 = {1300, "audit(1566400380.354:266): arch=c000003e syscall=42 success=yes exit=0 a0=4 a1=7fdf339232a0 a2=6e a3=ffffffb4 items=1 ppid=115255 pid=97970 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=\"sshd\" exe=\"/usr/sbin/sshd\" key=(null)"};


TEST_F(AuditRecAllocatorTests, pooling_of_audit_reply) {
  auto spa = std::make_shared<AuditRecAllocator>(3, 100);
  
  // allocate up to max of 3

  auto spbuf1 = spa->allocReply();
  ASSERT_TRUE(spbuf1 != nullptr);
  auto spbuf2 = spa->allocReply();
  ASSERT_TRUE(spbuf2 != nullptr);
  auto spbuf3 = spa->allocReply();
  ASSERT_TRUE(spbuf3 != nullptr);

  // the 4th should fail
  
  auto spbufx = spa->allocReply();
  ASSERT_TRUE(spbufx == nullptr);
  
  ASSERT_EQ(0, spa->smallPoolSize());

  // recycle the 3
  
  spa->recycle(spbuf3);
  ASSERT_EQ(1, spa->replyPoolSize());
  spa->recycle(spbuf1);
  ASSERT_EQ(2, spa->replyPoolSize());
  spa->recycle(spbuf2);
  ASSERT_EQ(3, spa->replyPoolSize());

  // get 3 out of pool
  
  spbuf1 = spa->allocReply();
  ASSERT_TRUE(spbuf1 != nullptr);
  ASSERT_EQ(2, spa->replyPoolSize());

  spbuf2 = spa->allocReply();
  ASSERT_TRUE(spbuf2 != nullptr);
  ASSERT_EQ(1, spa->replyPoolSize());

  spbuf3 = spa->allocReply();
  ASSERT_TRUE(spbuf3 != nullptr);
  ASSERT_EQ(0, spa->replyPoolSize());

  // 4th should fail

  spbufx = spa->allocReply();
  ASSERT_TRUE(spbufx == nullptr);

}

TEST_F(AuditRecAllocatorTests, pooling_of_small_bufs) {
  auto spa = std::make_shared<AuditRecAllocator>(2, 3);
  auto spReply = spa->allocReply();
  ASSERT_TRUE(spReply != nullptr);
  ASSERT_TRUE(spReply->capacity() > 8000); // exact comparison depends on audit_reply.msg.data[] in headers

  FILL_REPLY(spReply, rec1);
  
  // the following should allocate a new small buffer
  // (512 Bytes), and put the large spReply buffer back into the pool

  auto spBuf = spa->compact(spReply);
  ASSERT_TRUE(spBuf != nullptr);
  ASSERT_EQ(AUDIT_TYPICAL_BUF_MAXLEN, spBuf->capacity());
  ASSERT_EQ(0, spa->smallPoolSize());

  spa->recycle(spBuf);
  ASSERT_EQ(1, spa->smallPoolSize());

  spBuf = spa->compact(spa->allocReply());
  ASSERT_EQ(0, spa->smallPoolSize());

  auto spBuf2 = spa->compact(spa->allocReply());
  ASSERT_EQ(0, spa->smallPoolSize());
  auto spBuf3 = spa->compact(spa->allocReply());
  ASSERT_EQ(0, spa->smallPoolSize());

  spa->recycle(spBuf);
  spa->recycle(spBuf2);
  spa->recycle(spBuf3);
  ASSERT_EQ(3, spa->smallPoolSize());
}


TEST_F(AuditRecAllocatorTests, dups) {
  auto spa = std::make_shared<AuditRecAllocator>(2, 3);
  auto spReply = spa->allocReply();
  ASSERT_TRUE(spReply != nullptr);
  ASSERT_TRUE(spReply->capacity() > 8000); // exact comparison depends on audit_reply.msg.data[] in headers

  FILL_REPLY(spReply, rec1);
  
  size_t msglen = spReply->size();
  
  // the following should allocate a new small buffer
  // (512 Bytes), and put the large spReply buffer back into the pool
  
  auto spBuf = spa->compact(spReply);

  ASSERT_TRUE(spBuf != nullptr);
  EXPECT_EQ(msglen, spBuf->size());
  ASSERT_EQ(AUDIT_TYPICAL_BUF_MAXLEN, spBuf->capacity());
  ASSERT_EQ(0, spa->smallPoolSize());

  auto spBuf2 = spa->duplicate(spBuf);

  ASSERT_EQ(spBuf->size(), spBuf2->size());
  EXPECT_EQ(msglen, spBuf->size());
  
  EXPECT_EQ(0,strncmp(spBuf->data(), spBuf2->data(), spBuf->size()));
  EXPECT_EQ(0,memcmp(spBuf->data(true), spBuf2->data(true), spBuf->size() + sizeof(nlmsghdr)));

  spa->recycle(spBuf);
  spa->recycle(spBuf2);
  ASSERT_EQ(2, spa->smallPoolSize());
  
}
