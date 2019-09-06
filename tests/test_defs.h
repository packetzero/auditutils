#include <vector>

struct ExampleRec {
  uint32_t rectype;
  const std::string msg;
};

#include <auditutils/auditrec_parser.hpp>

static inline void FILL_REPLY(audit_reply &reply, const ExampleRec &rec) {
  memcpy(reply.msg.data, rec.msg.data(), rec.msg.size());
  reply.len = rec.msg.size();
  reply.type = rec.rectype;
}
