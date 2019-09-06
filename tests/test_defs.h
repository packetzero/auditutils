#include <vector>

struct ExampleRec {
  uint32_t rectype;
  const std::string msg;
};

#include <auditutils/auditrec_parser.hpp>

static inline void FILL_REPLY(SPAuditRecBuf spRecBuf, const ExampleRec &rec) {
  auto spReply = std::static_pointer_cast<AuditReplyBuf>(spRecBuf);
  strcpy(spReply->data(false), rec.msg.data());
  spReply->len = rec.msg.size();
  spReply->type = rec.rectype;
}
