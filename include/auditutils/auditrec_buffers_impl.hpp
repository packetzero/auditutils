#pragma once

#include <assert.h>
#include <list>
#include <map>
#include <memory>
#include <mutex>

#define AUDIT_TYPICAL_BUF_MAXLEN 512
/*
 * A simple 512 byte buffer that should hold most records.
 */
struct AuditTypicalBuf : public AuditRecBuf {

  static const int MAXLEN = AUDIT_TYPICAL_BUF_MAXLEN;

  AuditTypicalBuf(size_t len) : AuditRecBuf(),
  datavec_( (len <= 512) ? (512 + sizeof(nlmsghdr)) : (len + sizeof(nlmsghdr)) ), len_(0), type_(0) {
  }

  virtual ~AuditTypicalBuf() {
  }

  int getType() override {
    return type_;
  }

  char *data(bool withHeader) override {
    return (withHeader ? datavec_.data() : (datavec_.data() + sizeof(nlmsghdr) + fieldsOffset_));
  };

  size_t size() override {
    return len_ - fieldsOffset_;
  }

  size_t capacity() override {
    return datavec_.size() - sizeof(nlmsghdr);
  }

  void setOffset(int offset) override {
    fieldsOffset_ = offset;
  }

  std::vector<char> datavec_;
  int       len_;
  int       type_;
  int       fieldsOffset_ {0};
};


typedef std::shared_ptr<AuditTypicalBuf> SPAuditTypicalBuf;

/*
 * This is a wrapper around a buffer to contain the parsed fields.
 */
struct AuditRecState {
  AuditRecState(SPAuditRecBuf buf) : spBuf(buf), fields(), isProcessed(false) {}

  SPAuditRecBuf spBuf;
  std::map<std::string, string_offsets_t> fields;
  bool isProcessed;
};

/*
 * Manages a pool of audit_reply objects, as well as
 * smaller ones used for consolidation.
 */
struct AuditRecAllocator {
//  static const int DEFAULT_MAX_REPLY_BUFS = 50;
//  static const int DEFAULT_MAX_SMALL_BUFS = 500;

  /**
   * @param max_pool_size_small If 0, the smaller buffers will not
   *                            be pooled, only allocated shared_ptr.
   *                            Otherwise, sets a limit on number of
   *                            allocated shared_ptr.
   */
  AuditRecAllocator(size_t max_pool_size) : pool_(),
      mutex_(), max_pool_size_(max_pool_size) {
      }
  virtual ~AuditRecAllocator() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_ = 0;
    pool_.clear();
  }

  SPAuditRecBuf alloc(struct audit_message &temp, int type, int msglen, int preamble_size = 0) {
    std::lock_guard<std::mutex> lock(mutex_);

    SPAuditTypicalBuf spBuf;
    if (msglen <= AuditTypicalBuf::MAXLEN && !pool_.empty()) {
      spBuf = std::static_pointer_cast<AuditTypicalBuf>(pool_.front());
      pool_.pop_front();
    } else {
      if (max_pool_size_ > 0) {
        if (num_ >= max_pool_size_) {
          return nullptr;
        }
        num_++;
      }
      spBuf = std::make_shared<AuditTypicalBuf>(msglen);
    }

    _copyContents((char *)&temp, type, msglen, spBuf);
    spBuf->setOffset(preamble_size);

    return spBuf;
  }

  /**
   * Allocates a new buffer, copies message data and headers.
   * @returns nullptr if reached max_pool_size_small
   */
  SPAuditRecBuf duplicate(SPAuditRecBuf orig) {
    std::lock_guard<std::mutex> lock(mutex_);

    SPAuditTypicalBuf spBuf;
    if (!pool_.empty()) {
      spBuf = std::static_pointer_cast<AuditTypicalBuf>(pool_.front());
      pool_.pop_front();
    } else {
      if (max_pool_size_ > 0) {
        if (num_ >= max_pool_size_) {
          return nullptr;
        }
        num_++;
      }
      spBuf = std::make_shared<AuditTypicalBuf>(orig->size());
    }

    _copyContents(orig, spBuf);

    return spBuf;
  }

  size_t poolSize() {
    return pool_.size();
  }

  /**
   * Puts buffer back in pool
   */
  void recycle(SPAuditRecBuf obj)  {
    std::lock_guard<std::mutex> lock(mutex_);
    _recycle(obj);
  }

protected:
  void _recycle(SPAuditRecBuf obj)  {
    if (obj->size() > AuditTypicalBuf::MAXLEN) {
      // don't pool these, just let them get cleaned up
    } else {
      auto sp = std::static_pointer_cast<AuditTypicalBuf>(obj);
      sp->len_ = 0;
      sp->type_ = 0;
      pool_.push_back(obj);
    }
  }

  void _copyContents(SPAuditRecBuf orig, SPAuditTypicalBuf dest) {
    _copyContents(orig->data(true), orig->getType(), orig->size(), dest);
  }

  void _copyContents(char *paudit_message, int msgtype, int msglen, SPAuditTypicalBuf dest) {
    
    if (msglen < 26 || msglen > dest->capacity()) {
      assert(false);
      return;
    }
    
    // copy over header + message data
    
    memcpy(dest->data(true), paudit_message, msglen + (int)sizeof(nlmsghdr));
    
    dest->type_ = msgtype;
    dest->len_ = msglen;
    
    // make sure it's null-terminated
    
    dest->data(false)[dest->len_] = 0;
  }

  
  std::list<SPAuditRecBuf> pool_;
  std::mutex mutex_;
  uint32_t num_ {0};
  size_t max_pool_size_;
};
typedef std::shared_ptr<AuditRecAllocator> SPAuditRecAllocator;
