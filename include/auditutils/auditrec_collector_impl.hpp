#pragma once
#include <list>
#include <mutex>
#include <vector>


class AuditRecGroupImpl : public AuditRecGroup {
public:

  AuditRecGroupImpl(std::string serial, int64_t tsec, int32_t tms, SPAuditRecAllocator a) :
    AuditRecGroup(), header_(), records_(), allocator_(a) {
    header_.serial = serial;
    header_.tsec = tsec;
    header_.tms = tms;
  }

  virtual ~AuditRecGroupImpl() {
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

  /*
   * return type of first record or 0.
   */
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
        dest = std::string(prec->data() + fit->second.start, fit->second.len);
        return true;
      }
    }
    dest = defaultValue;
    return false;
  }

  /**
   * When application is finished with AuditRecGroup, it needs to call
   * release so that resources (buffers) can be recycled.
   */
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

typedef std::shared_ptr<AuditRecGroupImpl> SPAuditGroupImpl;


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
   */
  bool onAuditRecord(SPAuditRecBuf spRec) override {
    std::lock_guard<std::mutex> lock(mutex_);
    // sanity check

    auto msg = spRec->data();

    if (spRec->size() < 23 || msg[0] != 'a' || msg[5] != '(' || msg[20] != ':') {
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

    // if serial matches that of current group, no need to parse timestamps

    if (spCurrent_ == nullptr || serial != spCurrent_->getSerial()) {

      if (spCurrent_ != nullptr) {
        // we have an in-progress group, close and send it.
        flush();
      }

      // parse timestamp
      std::string secondstr = std::string(msg + 6, msg + 16);
      std::string millistr = std::string(msg + 17, msg + 20);
      auto ts = atol(secondstr.c_str());
      auto tms = atoi(millistr.c_str());

      spCurrent_ = std::make_shared<AuditRecGroupImpl>(serial, (int64_t)ts, (uint32_t)tms, allocator_);
    }

    size_t preamble_size = (p - msg) + 3;  // "): "

    // special case when no space after colon

    if (preamble_size > spRec->size()) { preamble_size = spRec->size(); }

    // note the length of preamble for when fields get parsed

    spRec->setOffset(preamble_size);

    // add record to current group

    spCurrent_->add(spRec);

    return false;
  }

  /**
   * If there's a current group, compact and send it.
   */
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
