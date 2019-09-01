#pragma once

#include <stdint.h>
#include <map>

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

struct AuditRecParserImpl  {
  AuditRecParserImpl()  {}
  virtual ~AuditRecParserImpl() {}

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
      entry.len = (uint32_t)(p - valueStart - (isQuoted ? 1 : 0));
      dest[key] = entry;

      // advance

      start = p + 1;
    }

    return false;

  }


protected:

};
