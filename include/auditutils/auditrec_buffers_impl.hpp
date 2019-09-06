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
    return (withHeader ? datavec_.data() : (datavec_.data() + sizeof(nlmsghdr)));
  };

  size_t size() override {
    return len_;
  }

  size_t capacity() override {
    return datavec_.size() - sizeof(nlmsghdr);
  }

  void setOffset(int offset) override {
  }

  std::vector<char> datavec_;
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

  /**
   * Allocates a new buffer, copies message data and headers.
   * @returns nullptr if reached max_pool_size_small
   */
  SPAuditRecBuf duplicate(SPAuditRecBuf orig) {
    std::lock_guard<std::mutex> lock(mutex_);

    SPAuditTypicalBuf spBuf;
    if (!small_pool_.empty()) {
      spBuf = std::static_pointer_cast<AuditTypicalBuf>(small_pool_.front());
      small_pool_.pop_front();
    } else {
      if (max_small_bufs_ > 0) {
        if (small_num_ >= max_small_bufs_) {
          return nullptr;
        }
        small_num_++;
      }
      spBuf = std::make_shared<AuditTypicalBuf>(orig->size());
    }

    _copyContents(orig, spBuf);

    return spBuf;
  }

  /*
   * Will replace AuditReplyBuf with AuditTypicalBuf
   * if possible, then recycle the AuditReplyBuf.
   */
  SPAuditRecBuf compact(SPAuditRecBuf spReply) {
    if (spReply->capacity() < 8000) {
      assert(false); // should not be calling compact for anything other than SPAuditReplyBuf
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
      spBuf = std::make_shared<AuditTypicalBuf>(spReply->size());
    }

    _copyContents(spReply, spBuf);

    // free up 8KB reply buf

    _recycle(spReply);

    return spBuf;
  }

  size_t smallPoolSize() {
    return small_pool_.size();
  }
  size_t replyPoolSize() {
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
    if (obj->capacity() > 8000) {
      auto sp = std::static_pointer_cast<AuditReplyBuf>(obj);
      sp->len = 0;
      sp->type = 0;
      sp->fieldsOffset_ = 0;
      memset(&sp->msg.hdr, 0, sizeof(sp->msg.hdr));
      pool_.push_back(obj);
    } else {
      if (obj->size() > AuditTypicalBuf::MAXLEN) {
        // don't pool these, just let them get cleaned up
      } else {
        auto sp = std::static_pointer_cast<AuditTypicalBuf>(obj);
        sp->len_ = 0;
        sp->type_ = 0;
        small_pool_.push_back(obj);
      }
    }
  }

  void _copyContents(SPAuditRecBuf orig, SPAuditTypicalBuf dest) {

    if (orig->size() > dest->capacity()) {
      assert(false);
      return;
    }

    // copy message data to small buf

    memcpy(dest->data(false), orig->data(), (int)orig->size());

    // copy over header

    memcpy(dest->data(true), orig->data(true), (int)sizeof(nlmsghdr));

    dest->type_ = orig->getType();
    dest->len_ = orig->size();

    // make sure it's null-terminated

    dest->data(false)[dest->len_] = 0;
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
