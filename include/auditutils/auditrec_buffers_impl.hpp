#pragma once

#include <list>
#include <map>
#include <memory>
#include <mutex>

/*
 * Wrapper around 8 KB audit_reply struct
 */
struct AuditReplyBuf : public audit_reply, AuditRecBuf {
  AuditReplyBuf() : audit_reply(), AuditRecBuf() {

  }
  virtual ~AuditReplyBuf() {
  }

  int getType() override {
    return type;
  }

  char *data() override {
    return msg.data + fieldsOffset_;
  };

  size_t size() override {
    return len - fieldsOffset_;
  }

  size_t capacity() override {
    return sizeof(msg.data);
  }

  void setOffset(int offset) override {
    fieldsOffset_ = offset;
  }

  // offset in bytes from start of msg.data[]
  size_t fieldsOffset_ {0};
};

/*
 * A simple 512 byte buffer that should hold most records.
 */
struct AuditTypicalBuf : public AuditRecBuf {

  static const int MAXLEN = 512;

  AuditTypicalBuf() : AuditRecBuf(), data_(), len_(0), type_(0) {
  }

  virtual ~AuditTypicalBuf() {
  }

  int getType() override {
    return type_;
  }

  char *data() override {
    return data_;
  };

  size_t size() override {
    return len_;
  }

  size_t capacity() override {
    return sizeof(data_);
  }

  void setOffset(int offset) override {
  }

  char data_[MAXLEN];
  int len_;
  int type_;
};


typedef std::shared_ptr<AuditReplyBuf> SPAuditReplyBuf;
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
  static const int MAX_REPLY_BUFS = 12;
  static const int MAX_SMALL_BUFS = 32;

  AuditRecAllocator() : pool_(), mutex_() {}
  virtual ~AuditRecAllocator() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_ = 0;
    pool_.clear();
  }

  SPAuditRecBuf allocReply()  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) {
      if (num_ >= MAX_REPLY_BUFS) {
        return nullptr;
      }
      num_++;
      return std::make_shared<AuditReplyBuf>();
    }
    auto obj = pool_.front();
    pool_.pop_front();
    return obj;
  }

  /*
   * Will replace AuditReplyBuf with AuditTypicalBuf
   * if possible, then recycle the AuditReplyBuf.
   */
  SPAuditRecBuf compact(SPAuditRecBuf spReply) {
    if (spReply->capacity() <= AuditTypicalBuf::MAXLEN) {
      // should not happen
      return spReply;
    }
    if (spReply->size() >= AuditTypicalBuf::MAXLEN) {
      return spReply;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    SPAuditTypicalBuf spBuf;
    if (!small_pool_.empty()) {
      spBuf = std::static_pointer_cast<AuditTypicalBuf>(small_pool_.front());
      small_pool_.pop_front();
    } else {
      if (small_num_ >= MAX_SMALL_BUFS) {
        return spReply;
      }
      small_num_++;
      spBuf = std::make_shared<AuditTypicalBuf>();
    }

    // copy details over to small buf

    memcpy(spBuf->data(), spReply->data(), (int)spReply->size());
    spBuf->type_ = spReply->getType();
    spBuf->len_ = spReply->size();

    // make sure it's null-terminated

    spBuf->data_[spBuf->len_] = 0;

    // free up 8KB reply buf

    _free(spReply);

    return spBuf;
  }

  void free(SPAuditRecBuf obj)  {
    std::lock_guard<std::mutex> lock(mutex_);
    _free(obj);
  }

  void _free(SPAuditRecBuf obj)  {
    if (obj->capacity() > AuditTypicalBuf::MAXLEN) {
      auto sp = std::static_pointer_cast<AuditReplyBuf>(obj);
      sp->len = 0;
      sp->type = 0;
      sp->fieldsOffset_ = 0;
      pool_.push_back(obj);
    } else {
      auto sp = std::static_pointer_cast<AuditTypicalBuf>(obj);
      sp->len_ = 0;
      sp->type_ = 0;
      small_pool_.push_back(obj);
    }
  }

  std::list<SPAuditRecBuf> pool_;
  std::list<SPAuditRecBuf> small_pool_;
  std::mutex mutex_;
  uint32_t num_ {0};
  uint32_t small_num_ {0};
};
typedef std::shared_ptr<AuditRecAllocator> SPAuditRecAllocator;
