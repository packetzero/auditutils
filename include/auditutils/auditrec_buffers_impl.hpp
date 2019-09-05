#pragma once

#include <assert.h>
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

  char *data(bool withHeader) override {
    if (withHeader) {
      return (char *)&msg.hdr;
    }
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

  char *data(bool withHeader) override {
    return (withHeader ? (char *)&hdr_ : data_);
  };

  size_t size() override {
    return len_;
  }

  size_t capacity() override {
    return sizeof(data_);
  }

  void setOffset(int offset) override {
  }

  nlmsghdr  hdr_;
  char      data_[MAXLEN];
  int       len_;
  int       type_;
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
//  static const int DEFAULT_MAX_REPLY_BUFS = 50;
//  static const int DEFAULT_MAX_SMALL_BUFS = 500;

  /**
   * @param max_pool_size_small If 0, the smaller buffers will not
   *                            be pooled, only allocated shared_ptr.
   *                            Otherwise, sets a limit on number of
   *                            allocated shared_ptr.
   */
  AuditRecAllocator(size_t max_pool_size_large, size_t max_pool_size_small) : pool_(),
      mutex_(), max_reply_bufs_(max_pool_size_large), max_small_bufs_(max_pool_size_small) {
        if (max_reply_bufs_ <= 0) {
          max_reply_bufs_ = 50; // 8KB each
        }
      }
  virtual ~AuditRecAllocator() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_ = 0;
    pool_.clear();
  }

  SPAuditRecBuf allocReply()  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) {
      if (num_ >= max_reply_bufs_) {
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
      assert(false); // should not happen
      return spReply;
    }
    if (spReply->size() >= AuditTypicalBuf::MAXLEN) {
      // TODO: handle this more gracefully.  Ideally use smaller buffer, not audit_reply
      return spReply;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    SPAuditTypicalBuf spBuf;
    if (!small_pool_.empty()) {
      spBuf = std::static_pointer_cast<AuditTypicalBuf>(small_pool_.front());
      small_pool_.pop_front();
    } else {
      if (max_small_bufs_ > 0) {
        if (small_num_ >= max_small_bufs_) {
          return spReply;
        }
        small_num_++;
      }
      spBuf = std::make_shared<AuditTypicalBuf>();
    }

    // copy message data to small buf

    memcpy(spBuf->data(false), spReply->data(), (int)spReply->size());

    // copy over header

    memcpy(spBuf->data(true), spReply->data(true), (int)sizeof(nlmsghdr));

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
      memset(&sp->msg.hdr, 0, sizeof(sp->msg.hdr));
      pool_.push_back(obj);
    } else {
      if (max_small_bufs_ == 0) {
        // Not pooling small bufs, shared pointer will be freed
      } else {
        auto sp = std::static_pointer_cast<AuditTypicalBuf>(obj);
        sp->len_ = 0;
        sp->type_ = 0;
        small_pool_.push_back(obj);
      }
    }
  }

  std::list<SPAuditRecBuf> pool_;
  std::list<SPAuditRecBuf> small_pool_;
  std::mutex mutex_;
  uint32_t num_ {0};
  uint32_t small_num_ {0};
  size_t max_reply_bufs_;
  size_t max_small_bufs_;
};
typedef std::shared_ptr<AuditRecAllocator> SPAuditRecAllocator;
