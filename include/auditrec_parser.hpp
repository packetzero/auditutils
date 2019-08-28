#pragma once

struct AuditGroupHdr {
  std::string serial;
  uint64_t tsec;
  uint32_t tms;
};

#ifdef __APPLE__

#include "linux_audit.h"
#include "linux_syscalls.h"

#else
#include <linux/audit.h>
#endif

struct AuditRecParser {

  virtual bool parse(uint32_t rectype, const char *msg, size_t msglen) = 0;

  virtual void clearState() = 0;
};

typedef std::shared_ptr<AuditRecParser> SPAuditRecParser;

struct AuditReply : public audit_reply {
};

typedef std::shared_ptr<AuditReply> SPAuditReply;

SPAuditRecParser AuditRecParserNew();


struct AuditGroup {

  virtual std::string getSerial() = 0;

  virtual uint64_t getTimeSeconds() = 0;

  virtual uint32_t getTimeMs() = 0;
  
  virtual AuditGroupHdr &getHeader() = 0;

  virtual size_t getNumMessages() = 0;
  
  virtual SPAuditReply getMessage(int i) = 0;

  /*
   * returns rectype of first message in group, or 0 if empty.
   */
  virtual int getType() = 0;
  
  virtual bool getField(int recType, const std::string &name, std::string &dest, std::string defaultValue) = 0;
};

typedef std::shared_ptr<AuditGroup> SPAuditGroup;

struct AuditListener {
  virtual bool onAuditRecords(SPAuditGroup spRecordGroup) = 0;
};
typedef std::shared_ptr<AuditListener> SPAuditListener;

struct AuditReplyAllocator {
  
  virtual SPAuditReply alloc() = 0;
  
  virtual void         free(SPAuditReply obj) = 0;
};

typedef std::shared_ptr<AuditReplyAllocator> SPAuditReplyAllocator;

struct AuditCollector {

  virtual SPAuditReplyAllocator allocator() = 0;
  
  virtual bool onAuditRecord(SPAuditReply spRec) = 0;
  
  virtual void clearState() = 0;
  
  virtual void releaseRecords(SPAuditGroup spRecordGroup) = 0;

};


#include "auditrec_parser_impl.hpp"
