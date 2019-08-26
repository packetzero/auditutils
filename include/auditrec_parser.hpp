#pragma once

struct AuditGroupHdr {
  std::string serial;
  uint64_t tsec;
  uint32_t tms;
};

#ifdef __APPLE__

#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1

struct audit_message {
  char   data[MAX_AUDIT_MESSAGE_LENGTH];
};

struct audit_reply {
  int                      type;
  int                      len;
  struct audit_message     msg;
};

#else
#include <linux/audit.h>
#endif

struct AuditRecParser {

  virtual bool parse(uint32_t rectype, const char *msg, size_t msglen) = 0;

  virtual void clearState() = 0;
};

typedef std::shared_ptr<AuditRecParser> SPAuditRecParser;

SPAuditRecParser AuditRecParserNew();

#include "auditrec_parser_impl.hpp"
