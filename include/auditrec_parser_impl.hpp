#pragma once

#include <list>
#include <map>
#include <mutex>
#include <vector>
//#include <unordered_map>

struct AuditRecFieldPtrs {
  const char *pkey;
  long        keyLen;
  const char *pvalue;
  long        valueLen;
};

struct string_offsets_t {
  const char *pstart;
  long len;
};

struct AuditRecParserImpl  {
  AuditRecParserImpl()  {}
  virtual ~AuditRecParserImpl() {}

  static bool parseFields(const char *body, int bodylen, std::map<std::string, string_offsets_t> &dest) {
    const char *start = body;
    const char *pend = body + bodylen;

    while (start < pend) {
      const char *p = start ;
      while (p != pend && *p != '=') {
        p++;
      }
      if (p == pend) {
        break;
      }
      const char *keyEnd = p;
      p++;
      if (p == pend) {
        return true;
      }
      const char *valueStart = p;
      bool isQuoted = false;
      char endChar = ' ';
      if (*p == '"') {
        isQuoted = true;
        endChar = '"';
        p++;
        valueStart = p;
      }
      // find end of value
      while (p != pend && (*p != endChar)) {
        p++;
      }
      auto key = std::string(start, (keyEnd - start));
      string_offsets_t entry = {valueStart, p - valueStart - (isQuoted ? 1 : 0)};
      dest[key] = entry;

      start = p + 1;
    }

    return false;

  }


protected:

};


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

// most records are smaller than 512 bytes

#define AUDIT_TYPICAL_BUF_LEN 512

struct AuditTypicalBuf : public AuditRecBuf {
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

  char data_[AUDIT_TYPICAL_BUF_LEN];
  int len_;
  int type_;
};


typedef std::shared_ptr<AuditReplyBuf> SPAuditReplyBuf;
typedef std::shared_ptr<AuditTypicalBuf> SPAuditTypicalBuf;

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
  
  SPAuditRecBuf compact(SPAuditRecBuf spReply) {
    if (spReply->capacity() <= AUDIT_TYPICAL_BUF_LEN) {
      // should not happen
      return spReply;
    }
    if (spReply->size() >= AUDIT_TYPICAL_BUF_LEN) {
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
    if (obj->capacity() > AUDIT_TYPICAL_BUF_LEN) {
      auto sp = std::static_pointer_cast<AuditReplyBuf>(obj);
      sp->len = 0;
      sp->type = 0;
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


class AuditGroupImpl : public AuditGroup {
public:

  AuditGroupImpl(std::string serial, int64_t tsec, int32_t tms, SPAuditRecAllocator a) :
    AuditGroup(), header_(), records_(), allocator_(a)
  {
    header_.serial = serial;
    header_.tsec = tsec;
    header_.tms = tms;
  }
  virtual ~AuditGroupImpl() {

  }

  void add(SPAuditRecBuf sp) {
    records_.push_back(AuditRecState(sp));
  }

  std::string getSerial() override {
    return header_.serial;
  }

  uint64_t getTimeSeconds()  override {
    return header_.tsec;
  }

  uint32_t getTimeMs() override {
    return header_.tms;
  }

  AuditGroupHdr &getHeader() override {
    return header_;
  }

  size_t getNumMessages() override {
    return records_.size();
  }

  SPAuditRecBuf getMessage(int i) override {
    if (i < 0 || i > records_.size()) return nullptr;
    return records_[i].spBuf;
  }

  void compact() {
    if (records_.size() <= 1) {
      return;
    }

    // replace with 8 KB buffers with 512 B buffers

    for (int i=0; i < records_.size(); i++) {
      records_[i].spBuf = allocator_->compact(records_[i].spBuf);
    }
  }
  
  // return type
  int getType() override {
    if (records_.empty()) return 0;
    return records_[0].spBuf->getType();
  }

  /*
   * return true if found
   */
  bool getField(int recType, const std::string &name, std::string &dest, std::string defaultValue) override {
    for (int i=0; i < records_.size(); i++) {
      auto &prec = records_[i].spBuf;
      if (recType != 0 && prec->getType() != recType) {
        continue;
      }
      if (!records_[i].isProcessed) {
        AuditRecParserImpl::parseFields(prec->data(),
                                        prec->size(),
                                        records_[i].fields);
        records_[i].isProcessed = true;
      }
      auto fit = records_[i].fields.find(name);
      if (fit != records_[i].fields.end()) {
        dest = std::string(fit->second.pstart, fit->second.len);
        return true;
      }
    }
    dest = defaultValue;
    return false;
  }

  void release() override {
    header_.serial = "";
    for (auto &rec : records_) {
      allocator_->free(rec.spBuf);
    }
    records_.clear();
  }

protected:
  AuditGroupHdr header_;

  std::vector<AuditRecState> records_;
  
  SPAuditRecAllocator allocator_;
};

typedef std::shared_ptr<AuditGroupImpl> SPAuditGroupImpl;


#define AUDIT_RECORD_TYPE_END_GROUP 1320          // contains no fields

class AuditCollectorImpl : public AuditCollector {
public:
  AuditCollectorImpl(SPAuditListener l) : AuditCollector(), spListener_(l),
  spCurrent_(), allocator_(std::make_shared<AuditRecAllocator>()) {
  }

  virtual ~AuditCollectorImpl() {}

  SPAuditRecBuf allocReply() override {
    return allocator_->allocReply();
  }

  /*
   * Preamble is of format:
   * "audit(1566400376.394:262):"
   * assumptions:
   * seconds and milliseconds are fixed length
   * serial not always 3 characters
   *
   * 
   */
  bool onAuditRecord(SPAuditRecBuf spRec) override {
    std::lock_guard<std::mutex> lock(mutex_);
    // sanity check

    auto msg = spRec->data();

    if (spRec->size() < 24 || msg[0] != 'a' || msg[5] != '(' || msg[20] != ':') {
      allocator_->free(spRec);
      return true;
    }
    // preamble start: "audit(1566400374.798:" + serial + "):"

    if (spRec->getType() == AUDIT_RECORD_TYPE_END_GROUP) {
      allocator_->free(spRec);
      flush();
      return false;
    }
    
    const char *pend = msg + spRec->size();
    const char *p = msg + 21;
    const char *start = p;

    // find trailing brace after serial

    while (p < pend && *p != ')') p++;
    if (*p != ')') {
      allocator_->free(spRec);
      return true;
    }

    // extract serial

    std::string serial = std::string(start, p - start);

    if (spCurrent_ == nullptr || serial != spCurrent_->getSerial()) {

      if (spCurrent_ != nullptr && spListener_ != nullptr) {
        flush();
      }

      // parse timestamp
      std::string secondstr = std::string(msg + 6, msg + 16);
      std::string millistr = std::string(msg + 17, msg + 20);
      auto ts = atol(secondstr.c_str());
      auto tms = atoi(millistr.c_str());

      spCurrent_ = std::make_shared<AuditGroupImpl>(serial, (int64_t)ts, (uint32_t)tms, allocator_);
    }

    size_t preamble_size = (p - msg) + 3;  // "): "
    spRec->setOffset(preamble_size);
    spCurrent_->add(spRec);

    return false;
  }


  virtual void flush() override {
    if (spCurrent_ != nullptr) {

      spCurrent_->compact();

      if (spListener_ != nullptr) {
        spListener_->onAuditRecords(spCurrent_);
      }
    }
    spCurrent_ = nullptr;
  }


protected:

  SPAuditListener spListener_;
  SPAuditGroupImpl spCurrent_;
  std::shared_ptr<AuditRecAllocator> allocator_;
  std::mutex mutex_;
};

SPAuditCollector AuditCollectorNew(SPAuditListener listener) {
  return std::make_shared<AuditCollectorImpl>(listener);
}
