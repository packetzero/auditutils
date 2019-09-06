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



TEST_F(AuditRecAllocatorTests, pooling_of_small_bufs) {
  auto spa = std::make_shared<AuditRecAllocator>(3);

  audit_reply reply;
  FILL_REPLY(reply, rec1);
  
  auto spBuf = spa->alloc(reply.msg, reply.type, reply.len);
  ASSERT_TRUE(spBuf != nullptr);
  ASSERT_EQ(AUDIT_TYPICAL_BUF_MAXLEN, spBuf->capacity());
  ASSERT_EQ(0, spa->poolSize());

  spa->recycle(spBuf);
  ASSERT_EQ(1, spa->poolSize());

  spBuf = spa->alloc(reply.msg, reply.type, reply.len);
  ASSERT_EQ(0, spa->poolSize());

  auto spBuf2 = spa->alloc(reply.msg, reply.type, reply.len);
  ASSERT_EQ(0, spa->poolSize());
  auto spBuf3 = spa->alloc(reply.msg, reply.type, reply.len);
  ASSERT_EQ(0, spa->poolSize());

  spa->recycle(spBuf);
  spa->recycle(spBuf2);
  spa->recycle(spBuf3);
  ASSERT_EQ(3, spa->poolSize());
}


TEST_F(AuditRecAllocatorTests, dups) {
  auto spa = std::make_shared<AuditRecAllocator>(3);

  audit_reply reply;
  FILL_REPLY(reply, rec1);
  
  auto spBuf = spa->alloc(reply.msg, reply.type, reply.len);
  
  ASSERT_TRUE(spBuf != nullptr);
  EXPECT_EQ(reply.len, spBuf->size());
  ASSERT_EQ(AUDIT_TYPICAL_BUF_MAXLEN, spBuf->capacity());
  ASSERT_EQ(0, spa->poolSize());

  auto spBuf2 = spa->duplicate(spBuf);

  ASSERT_EQ(spBuf->size(), spBuf2->size());
  EXPECT_EQ(reply.len, spBuf->size());
  
  EXPECT_EQ(0,strncmp(spBuf->data(), spBuf2->data(), spBuf->size()));
  EXPECT_EQ(0,memcmp(spBuf->data(true), spBuf2->data(true), spBuf->size() + sizeof(nlmsghdr)));

  spa->recycle(spBuf);
  spa->recycle(spBuf2);
  ASSERT_EQ(2, spa->poolSize());
  
}
