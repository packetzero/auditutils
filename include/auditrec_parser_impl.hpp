#pragma once

#include <list>
#include <mutex>
#include <unordered_map>

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
    //fields_.clear();
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
  
//  std::map<std::string, string_offsets_t> fields_;
  
//  bool isProcessed_ { false };
};

typedef std::shared_ptr<AuditReplyBuf> SPAuditReplyBuf;

struct AuditRecState {
  AuditRecState(SPAuditRecBuf buf) : spBuf(buf), fields(), isProcessed(false) {}

  SPAuditRecBuf spBuf;
  std::map<std::string, string_offsets_t> fields;
  bool isProcessed;
};

struct AuditRecAllocator {
  
  virtual SPAuditRecBuf alloc() = 0;
  
  virtual void         free(SPAuditRecBuf obj) = 0;
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
        AuditRecParserImpl::parseFields(prec->data(), //msg.data + prec->fieldsOffset_,
                                        prec->size(),// - prec->fieldsOffset_,
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
    for (auto &rec : records_) { allocator_->free(rec.spBuf); }
    records_.clear();
  }

protected:
  AuditGroupHdr header_;

  std::vector<AuditRecState> records_;
  
  SPAuditRecAllocator allocator_;
};

typedef std::shared_ptr<AuditGroupImpl> SPAuditGroupImpl;

struct AuditReplyAllocatorImpl : public AuditRecAllocator {

  AuditReplyAllocatorImpl() : AuditRecAllocator(), pool_(), mutex_() {}
  virtual ~AuditReplyAllocatorImpl() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_ = 0;
    pool_.clear();
  }

  SPAuditRecBuf alloc() override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) {
      // TODO: enforce max-allocated
      num_++;
      return std::make_shared<AuditReplyBuf>();
    }
    auto obj = pool_.front();
    pool_.pop_front();
    return obj;
  }

  void         free(SPAuditRecBuf obj) override {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.push_back(obj);
  }

  std::list<SPAuditRecBuf> pool_;
  std::mutex mutex_;
  uint32_t num_ {0};
};

class AuditCollectorImpl : public AuditCollector {
public:
  AuditCollectorImpl(SPAuditListener l) : AuditCollector(), spListener_(l),
  spCurrent_(), allocator_(std::make_shared<AuditReplyAllocatorImpl>()) {
  }

  virtual ~AuditCollectorImpl() {}

  SPAuditRecBuf allocReply() override {
    return allocator_->alloc();
  }

  /*
   * Preamble is of format:
   * "audit(1566400376.394:262):"
   * assumptions:
   * seconds and milliseconds are fixed length
   * serial not always 3 characters
   */

  bool onAuditRecord(SPAuditRecBuf spRec) override {
    std::lock_guard<std::mutex> lock(mutex_);
    // sanity check

    auto msg = spRec->data();

    if (spRec->size() < 24 || msg[0] != 'a' || msg[5] != '(' || msg[20] != ':') {
      return true;
    }
    // preamble start: "audit(1566400374.798:" + serial + "):"

    const char *pend = msg + spRec->size();
    const char *p = msg + 21;
    const char *start = p;

    // find trailing brace after serial

    while (p < pend && *p != ')') p++;
    if (*p != ')') { return true; }

    // extract serial

    std::string serial = std::string(start, p - start);

    if (spCurrent_ == nullptr || serial != spCurrent_->getSerial()) {

      if (spCurrent_ != nullptr && spListener_ != nullptr) {
        spListener_->onAuditRecords(spCurrent_);
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
      if (spListener_ != nullptr) {
        spListener_->onAuditRecords(spCurrent_);
      }
    }
    spCurrent_ = nullptr;
  }


protected:

  SPAuditListener spListener_;
  SPAuditGroupImpl spCurrent_;
  std::shared_ptr<AuditReplyAllocatorImpl> allocator_;
  std::mutex mutex_;
};

SPAuditCollector AuditCollectorNew(SPAuditListener listener) {
  return std::make_shared<AuditCollectorImpl>(listener);
}
