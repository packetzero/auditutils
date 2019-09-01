#pragma once

struct AuditGroupHdr {
  std::string serial;
  uint64_t tsec;
  uint32_t tms;
};

#ifdef __APPLE__

#include "_x_linux_audit.h"
#include "_x_linux_syscalls.h"

#else
#include <linux/audit.h>
#endif

/*
 * Abstraction for an audit_reply struct.
 * The audit_reply has a fixed msg.data[] size of 8192 chars.
 * This allows application to transfer data to smaller record buffers
 * for processing.
 */
struct AuditRecBuf {

  /*
   * audit record type
   */
  virtual int          getType() = 0;

  /*
   * Data buffer pointer + offset.
   */
  virtual char *       data() = 0;

  /*
   * data size - offset
   */
  virtual size_t       size() = 0;

  /*
   * Total capacity of data.
   */
  virtual size_t       capacity() = 0;

  /*
   * Usually used to skip over preamble.
   */
  virtual void         setOffset(int offset) = 0;
};

typedef std::shared_ptr<AuditRecBuf> SPAuditRecBuf;

struct AuditRecGroup {

  virtual std::string     getSerial() = 0;

  virtual uint64_t        getTimeSeconds() = 0;

  virtual uint32_t        getTimeMs() = 0;

  virtual AuditGroupHdr & getHeader() = 0;

  virtual size_t          getNumMessages() = 0;

  virtual SPAuditRecBuf   getMessage(int i) = 0;

  /*
   * returns record type of first message in group, or 0 if empty.
   */
  virtual int getType() = 0;

  /*
   * Find field with key 'name' and populate dest with the value.
   * If recType != 0, will only search records with that type for the
   * field.
   * If field not found, dest will be set to defaultValue.
   * @return true if found, false otherwise.
   */
  virtual bool getField(int recType, const std::string &name, std::string &dest, std::string defaultValue) = 0;

  /*
   * Called by application when done accessing all records and fields.
   * This will cause the record buffers to be freed or put back in pool.
   */
  virtual void release() = 0;
};

typedef std::shared_ptr<AuditRecGroup> SPAuditGroup;

struct AuditListener {
  /*
   * Called for a group of one or more consecutive records with same
   * serial number.  The application receives ownership of spRecordGroup,
   * and must call spRecordGroup->release() when finished with it.
   */
  virtual bool onAuditRecords(SPAuditGroup spRecordGroup) = 0;
};
typedef std::shared_ptr<AuditListener> SPAuditListener;

/*
 * The application is responsible for reading the auditd socket,
 * filling an AuditRecBuf and passing it to the
 * AuditCollector.onAuditRecord().  The collector assumes ownership
 * of the AuditRecBuf.
 * The AuditCollector will group together messages with the same serial
 * and pass to the AuditListener.onAuditRecords().
 * Usage:
 *
 * auto spCollector = AuditCollectorNew(myListener);
 * auto spReply = spCollector->allocReply();
 *
 * // read from socket and fill spReply->data()
 *
 * spCollector->onAuditRecord(spReply);
 *
 */
struct AuditCollector {

  /*
   * Abstraction to get an AuditRecBuf (e.g. audit_reply)
   * to allow for pooling and other optimizations.
   */
  virtual SPAuditRecBuf allocReply() = 0;

  /*
   * Pass on auditd reply to collector for grouping and processing
   * so that listener may receive it.
   */
  virtual bool onAuditRecord(SPAuditRecBuf spRec) = 0;

  /**
   * Application calls flush() to indicate that all records have arrived, and
   * to pass on any cached records being grouped to the listener.
   */
  virtual void flush() = 0;
};

typedef std::shared_ptr<AuditCollector> SPAuditCollector;

// SPAuditCollector AuditCollectorNew(SPAuditListener listener);

#include "auditrec_parser_impl.hpp"
#include "auditrec_buffers_impl.hpp"
#include "auditrec_collector_impl.hpp"
