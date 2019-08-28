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

struct AlNum {
  static inline unsigned int CVAL(const char c) {
    return _lut()[(uint8_t)c];
  }
  static bool _initLut(uint8_t *lut) {
    for (int i=0; i < 256; i++) { lut[i] = (uint8_t)0; }
    for (auto i='0'; i <= '9'; i++) { lut[(int)i] = (uint8_t)(i - '0'); }
    for (auto i='A'; i <= 'Z'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'A');}
    for (auto i='a'; i <= 'z'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'a');}
    lut[(int)'_'] = 36 + 1;
    return true;
  }
  static uint8_t* _lut() {
    static uint8_t lut[256];
    static bool isInitialized=_initLut(lut);
    return lut;
  }
};

struct string_offsets_t {
  const char *pstart;
  long len;
};

struct AuditRecParserImpl : public AuditRecParser {
  static const int HAVE_ALL_FIELDS_FOR_THIS_RECORD = -1;
  AuditRecParserImpl() : AuditRecParser(), currentGroup_(), mapWantedFields_() {}
  virtual ~AuditRecParserImpl() {}

  bool parse(uint32_t rectype, const char *msg, size_t msglen) override {
    size_t preamble_size = 0;
    if (parse_preamble(msg, msglen, preamble_size)) {
      return true;
    }

    // rectype = 1320 has no body

    if ((msglen - preamble_size) <= 1) {
      return false;
    }

    if (parse_body(rectype, msg + preamble_size, msglen - preamble_size)) {
      return true;
    }

    return false;
  }

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

  bool parse_body(uint32_t rectype, const char *body, size_t bodylen) {
    const char *start = body;
    const char *pend = body + bodylen;
    AuditRecFieldPtrs ptrs;

    std::map<std::string, std::string> rec;

    auto fit = mapWantedFields_.find(rectype);
    if (fit == mapWantedFields_.end()) {
      return false;
    }

    std::vector<KeyState> keyStates;
    initKeyState(fit->second, keyStates);

    // TODO: if starts with avc, handle special SELinux case

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
      ptrs = {start, (keyEnd - start), valueStart, p - valueStart - (isQuoted ? 1 : 0)};
      if (onField(rectype, ptrs, keyStates, fit->second, rec) == HAVE_ALL_FIELDS_FOR_THIS_RECORD) {
        break;
      }
      
      start = p + 1;
    }

    return false;
  }

  /*
   * Parses preamble
   * "audit(1566400376.394:262):"
   * assumptions:
   * seconds and milliseconds are fixed length
   * serial not always 3 characters
   */
  bool parse_preamble(const char *msg, size_t msglen, size_t &preamble_size) {

    // sanity check

    if (msglen < 24 || msg[0] != 'a' || msg[5] != '(' || msg[20] != ':') {
      return true;
    }
    // preamble start: "audit(1566400374.798:" + serial + "):"

    const char *pend = msg + msglen;
    const char *p = msg + 21;
    const char *start = p;

    // find trailing brace after serial
    
    while (p < pend && *p != ')') p++;
    if (*p != ')') { return true; }

    // extract serial
    
    std::string serial = std::string(start, p - start);

    if (serial != currentGroup_.serial) {
      // parse timestamp
      std::string secondstr = std::string(msg + 6, msg + 16);
      std::string millistr = std::string(msg + 17, msg + 20);
      currentGroup_.tsec = atol(secondstr.c_str());
      currentGroup_.tms = atol(millistr.c_str());
      currentGroup_.serial = serial;
    }
    
    preamble_size = (p - msg) + 3;  // "): "
    
    return false;
  }

  void clearState() override {
    currentGroup_ = AuditGroupHdr();
  }
protected:
  
  struct KeyState {
    uint64_t hash;
    bool isSet;
  };

  struct KeyInfo {
    std::string key;
    uint64_t hash;
  };
  
  void initKeyState(std::vector<KeyInfo> &wantedFields, std::vector<KeyState> &keyStates) {
    keyStates.resize(wantedFields.size());
    for (int i=0; i < wantedFields.size(); i++) {
      keyStates[i] = { wantedFields[i].hash, false };
    }
  };

  uint64_t hashKeyName(const char *p, size_t len) {
    uint64_t value = 0;
    auto pend = p + len;
    while (p < pend) {
      value = value << 6 | AlNum::CVAL(*p);
      p++;
    }
    return value;
  }
  
  int onField(uint32_t rectype, AuditRecFieldPtrs &info,
              std::vector<KeyState> &keyStates, std::vector<KeyInfo> &wantedFields,
              std::map<std::string, std::string> &rec) {

    KeyInfo *pWantedField = nullptr;

    if (!keyStates.empty()) {
      int numFieldsLeft = 0;
      auto keyHash = hashKeyName(info.pkey, info.keyLen);
      for (int i=0; i < keyStates.size(); i++) {
        auto & state = keyStates[i];
        if (state.isSet) {
          continue;
        }

        numFieldsLeft ++;

        if (state.hash == keyHash) {
          state.isSet = true;
          pWantedField = &wantedFields[i];
          break;
        }
      }
      if (numFieldsLeft == 0) {
        return HAVE_ALL_FIELDS_FOR_THIS_RECORD;
      }
      if (nullptr == pWantedField) { return 0; }
    }
    
    // if we get here, user wants this field
    std::string keyName = (pWantedField != nullptr ? pWantedField->key : std::string(info.pkey, info.keyLen) );
    rec[ keyName ] = std::string(info.pvalue, info.valueLen);

    return 1;
  }
  
  AuditGroupHdr currentGroup_;
  std::unordered_map<uint32_t, std::vector<KeyInfo> > mapWantedFields_;
};

SPAuditRecParser AuditRecParserNew() {
  return std::make_shared<AuditRecParserImpl>();
}


struct AuditReplyExt : AuditReply {

  AuditReplyExt() : AuditReply(), fields_() {}

  virtual ~AuditReplyExt() {
    fields_.clear();
  }

  // offset in bytes from start of msg.data[]
  size_t fieldsOffset_ {0};
  
  std::map<std::string, string_offsets_t> fields_;

  bool isProcessed_ { false };
};

typedef std::shared_ptr<AuditReplyExt> SPAuditReplyExt;

class AuditGroupImpl : public AuditGroup {
public:

  AuditGroupImpl(std::string serial, int64_t tsec, int32_t tms) :
    AuditGroup(), header_(), replies_(), replyFields_()
  {
    header_.serial = serial;
    header_.tsec = tsec;
    header_.tms = tms;
  }
  virtual ~AuditGroupImpl() {
    
  }

  void add(SPAuditReply spReply, size_t preamble_size) {
    auto sp = std::static_pointer_cast<AuditReplyExt>(spReply);
    sp->fieldsOffset_ = preamble_size;
    replies_.push_back(sp);
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
    return replies_.size();
  }
  
  SPAuditReply getMessage(int i) override {
    if (i < 0 || i > replies_.size()) return nullptr;
    return replies_[i];
  }

  // return type
  int getType() override {
    if (replies_.empty()) return 0;
    return replies_[0]->type;
  }
  
  bool getField(int recType, const std::string &name, std::string &dest, std::string defaultValue) override {
    for (int i=0; i < replies_.size(); i++) {
      auto &prec = replies_[i];
      if (recType != 0 && prec->type != recType) {
        continue;
      }
      if (!prec->isProcessed_) {
        AuditRecParserImpl::parseFields(prec->msg.data + prec->fieldsOffset_,
                                        prec->len - prec->fieldsOffset_,
                                        prec->fields_);
        prec->isProcessed_ = true;
      }
      auto fit = prec->fields_.find(name);
      if (fit != prec->fields_.end()) {
        dest = std::string(fit->second.pstart, fit->second.len);
        return false;
      }
    }
    dest = defaultValue;
    return true;
  }
  
  void clear(SPAuditReplyAllocator allocator) {
    header_.serial = "";
    replyFields_.clear();
    while (!replies_.empty()) {
      allocator->free(replies_[0]);
      replies_.erase(replies_.begin());
    }
  }

protected:
  AuditGroupHdr header_;

  std::vector<SPAuditReplyExt> replies_;
  std::vector< std::map<std::string,std::string> > replyFields_;
};

typedef std::shared_ptr<AuditGroupImpl> SPAuditGroupImpl;

struct AuditReplyAllocatorImpl : public AuditReplyAllocator {

  AuditReplyAllocatorImpl() : AuditReplyAllocator(), pool_(), mutex_() {}
  virtual ~AuditReplyAllocatorImpl() {
    std::lock_guard<std::mutex> lock(mutex_);
    num_ = 0;
    pool_.clear();
  }

  SPAuditReply alloc() override {
    std::lock_guard<std::mutex> lock(mutex_);
    if (pool_.empty()) {
      // TODO: enforce max-allocated
      num_++;
      return std::make_shared<AuditReplyExt>();
    }
    auto obj = pool_.front();
    pool_.pop_front();
    return obj;
  }
  
  void         free(SPAuditReply obj) override {
    std::lock_guard<std::mutex> lock(mutex_);
    pool_.push_back(std::static_pointer_cast<AuditReplyExt>(obj));
  }

  std::list<SPAuditReplyExt> pool_;
  std::mutex mutex_;
  uint32_t num_ {0};
};

class AuditCollectorImpl : public AuditCollector {
public:
  AuditCollectorImpl(SPAuditListener l) : AuditCollector(), spListener_(l),
  spCurrent_(), allocator_(std::make_shared<AuditReplyAllocatorImpl>()) {
  }

  virtual ~AuditCollectorImpl() {}

  SPAuditReply allocReply() override {
    return allocator_->alloc();
  }

  /*
   * Preamble is of format:
   * "audit(1566400376.394:262):"
   * assumptions:
   * seconds and milliseconds are fixed length
   * serial not always 3 characters
   */

  bool onAuditRecord(SPAuditReply spRec) override {
    std::lock_guard<std::mutex> lock(mutex_);
    // sanity check
    
    auto msg = spRec->msg.data;
    
    if (spRec->len < 24 || msg[0] != 'a' || msg[5] != '(' || msg[20] != ':') {
      return true;
    }
    // preamble start: "audit(1566400374.798:" + serial + "):"
    
    const char *pend = msg + spRec->len;
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
      
      spCurrent_ = std::make_shared<AuditGroupImpl>(serial, (int64_t)ts, (uint32_t)tms);
    }

    size_t preamble_size = (p - msg) + 3;  // "): "
    spCurrent_->add(spRec, preamble_size);
    
    return false;
  }

  void releaseRecords(SPAuditGroup spRecordGroup) override {
    auto spg = std::static_pointer_cast<AuditGroupImpl>(spRecordGroup);
    spg->clear(allocator_);
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
