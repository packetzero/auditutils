#pragma once

#include <stdint.h>
#include <map>
#include <set>

/*
 * Since we don't know which fields will be requested by application,
 * we parse and note the offsets of the field values.
 * AuditRecGroupImpl.getField() will construct the value strings when
 * requested.
 */
struct string_offsets_t {
  uint32_t start;
  uint32_t len;
};

struct AuditRecFieldsParser {
  virtual bool handlesType(int recType) = 0;
  virtual bool parseFields(int recType, const char *body, int bodylen, std::map<std::string, string_offsets_t> &dest) = 0;
};

struct DefaultAuditRecFieldParser  {

  /**
   * Parses the post-preamble body of Audit record message
   * and populates 'dest' parameter which is map of fieldname => offset,len of value.
   *
   * NOTE: Does not support SELinux format
   * @param body string starting with first "fieldname="
   * @param bodylen number of bytes in body
   * @param dest map to populate with field details
   *
   * audit message: "audit(1566400374.494:256): arch=c000003e syscall=42 succ..."
   * preamble: "audit(1566400374.494:256): "
   * body: "arch=c000003e syscall=42 succ..."
   *
   * @return true on parse error, false on success
   */

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

      // add entry to dest

      auto key = std::string(start, (keyEnd - start));
      string_offsets_t entry;
      entry.start = (uint32_t)(valueStart - body);
      entry.len = (uint32_t)(p - valueStart );
      dest[key] = entry;

      // advance

      start = p + (isQuoted ? 2 : 1);
    }
    return false;
  }
};


struct AuditRecParsers {
  AuditRecParsers() : mutex_(), addedParsers_() {  }

  bool parseFields(int recType, const char *body, int bodylen, std::map<std::string, string_offsets_t> &dest) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!addedParsers_.empty()) {
      for (auto spParser : addedParsers_) {
        if (spParser->handlesType(recType)) {
          return spParser->parseFields(recType, body, bodylen, dest);
        }
      }
    }
    return DefaultAuditRecFieldParser::parseFields(body, bodylen, dest);
  }

  void addFieldsParser(std::shared_ptr<AuditRecFieldsParser> spParser) {
    std::lock_guard<std::mutex> lock(mutex_);
    addedParsers_.insert(spParser);
  }
  void removeFieldsParser(std::shared_ptr<AuditRecFieldsParser> spParser) {
    std::lock_guard<std::mutex> lock(mutex_);
    addedParsers_.erase(spParser);
  }

  static AuditRecParsers& getInstance() {
    static AuditRecParsers _inst;
    return _inst;
  }
protected:
    std::mutex mutex_;
    std::set<std::shared_ptr<AuditRecFieldsParser> > addedParsers_;
};

struct SELinuxFieldsParser : public AuditRecFieldsParser {
  virtual ~SELinuxFieldsParser() {}
  bool handlesType(int recType) override {
    return (recType == 1107 || (recType >= 1400 || recType <= 1450));
  }
  bool parseFields(int recType, const char *body, int bodylen, std::map<std::string, string_offsets_t> &dest) override {
    const char *start = body;
    const char *pend = body + bodylen;
    int i=0;

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

      // add entry to dest

      auto key = std::string(start, (keyEnd - start));
      string_offsets_t entry;
      entry.start = (uint32_t)(valueStart - body);
      entry.len = (uint32_t)(p - valueStart);

      if (i++ == 0) {
        // the first key is where the special handling comes into play
        handleSpecialIntro(key, entry, dest);
      } else {
        dest[key] = entry;
      }

      // advance

      start = p + (isQuoted ? 2 : 1);
    }
    return false;
  }

  // cases:
  //   'avc: granted { transition } for pid=7687 ' # _avc_status=granted, _avc_op=transition, strip off 'for'
  //   'policy loaded auid=0 ses=2' # _policy_status=loaded
  //   'netlabel: auid=0 ses=2 '  # _sel_prefix='netlabel'
  //   'user pid=1169'  # _sel_prefix='user'
  void handleSpecialIntro(std::string &key, string_offsets_t &entry, std::map<std::string, string_offsets_t> &dest) {

    std::size_t posLastSpace = key.rfind(" ");
    std::size_t posFirstSpace = key.find(" ");
    if (posLastSpace == std::string::npos) {
      // use verbatim
      dest[key] = entry;
      return;
    }


    std::string actualKey = key.substr(posLastSpace+1);
    dest[actualKey] = entry;
    
    // now handle special info
    
    const char *end = key.data() + posLastSpace;

    // prefix only?  'user' or 'netlabel:'
    
    if (posFirstSpace == posLastSpace) {
      //std::string prefix = key.substr(0, posFirstSpace);
      dest["_sel_prefix"] = string_offsets_t({0, (uint32_t)posFirstSpace});
      return;
    }

    // avc: some_status { some_action } for pid

    if (posFirstSpace == 4 && key[0] == 'a' && key[3] == ':') {
      // find status
      const char *p = key.data() + 5;
      const char *start = p;
      while (p < end && *p != ' ') {
        p++;
      }
      if (p >= end) {
        return;  // did not find
      }
      //std::string avcStatus = key.substr(5,(p-start));
      dest["_avc_status"] = string_offsets_t({5,(uint32_t)(p-start)});
      
      start = p + 3;
      p = start;
      while (p < end && *p != '}') {
        p++;
      }

      if (p >= end) {
        return;  // did not find
      }
      //std::string avcOp = key.substr(start-key.data(),(p-start-1));
      dest["_avc_op"] = string_offsets_t({(uint32_t)(start-key.data()),(uint32_t)(p-start-1)});
    }
    else if (posFirstSpace == 6 && key[0] == 'p' && key[5] == 'y') {
      //std::string policyStatus = key.substr(posFirstSpace+1,posLastSpace-posFirstSpace-1);
      dest["_policy_status"] = string_offsets_t({(uint32_t)(posFirstSpace+1),(uint32_t)(posLastSpace-posFirstSpace-1)});
    }
  }
};

namespace {
std::shared_ptr<AuditRecFieldsParser> SELinuxFieldsParserNew() {
  return std::make_shared<SELinuxFieldsParser>();
}
}
