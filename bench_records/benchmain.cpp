#include <auditutils.hpp>
#include <sstream>
#include <auditrec_parser.hpp>
#include <unistd.h>

#include "../tests/example_records.hpp"

/*
 * This application exercises the parsing and processing of auditd
 * records.
 */

struct MyAuditListener : public AuditListener {
  virtual ~MyAuditListener() {}
  bool onAuditRecords(SPAuditGroup spRecordGroup) override {
    spRecordGroup->release();
    return false;
  }
  void cleanup() {
  }
};

static inline void FILL_REPLY(SPAuditRecBuf spRecBuf, const ExampleRec &rec) {
  auto spReply = std::static_pointer_cast<AuditReplyBuf>(spRecBuf);
  strcpy(spReply->data(), rec.msg.data());
  spReply->len = rec.msg.size();
  spReply->type = rec.rectype;
}

void run(size_t loopCount) {
  auto listener = std::make_shared<MyAuditListener>();
  auto spCollector = AuditCollectorNew(listener);
  
  for (size_t i = 0; i < loopCount; i++) {

    for (int i=0; i < ex1_records.size(); i++) {
      auto spReply = spCollector->allocReply();
      FILL_REPLY(spReply, ex1_records[i]);
      
      spCollector->onAuditRecord(spReply);
      usleep(2);
    }
    spCollector->flush();

    usleep(50);
  }
}



int main(int argc, char *argv[])
{
  size_t loopCount = 5000000;
  run(loopCount);

}
