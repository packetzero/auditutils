#pragma once

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
