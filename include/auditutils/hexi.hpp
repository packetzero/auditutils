#pragma once

struct Hexi {
  /*
   * Parse 2-char hex to byte.
   * Caller must ensure str has length.
   */
  static uint8_t parseU8(const char *str) {
    return CVAL(str[0]) << 4 | CVAL(str[1]);
  }

  /*
   * Parse 4-char hex to unsigned short 16-bit.
   * Caller must ensure str has length.
   */
  static uint16_t parseU16(const char *str) {
    uint16_t value = CVAL(str[0]) << 12 | CVAL(str[1]) << 8;
    value |= CVAL(str[2]) << 4 | CVAL(str[3]);
    return value;
  }

  /*
   * Parse 8-char hex to unsigned 32-bit int.
   * Caller must ensure str has length.
   */
  static uint32_t parseU32(const char *str) {
    uint32_t val = 0;
    val |= CVAL(*str++) << 28;
    val |= CVAL(*str++) << 24;
    val |= CVAL(*str++) << 20;
    val |= CVAL(*str++) << 16;
    val |= CVAL(*str++) << 12;
    val |= CVAL(*str++) << 8;
    val |= CVAL(*str++) << 4;
    val |= CVAL(*str++);
    return val;
  }

  /**
   * decodes hex-encoded string
   * @return true on error, false on success.
   */
  static bool hex2ascii(std::string &dest, const std::string &src) {
    auto srclen = src.size();
    if (srclen < 2 || srclen % 2 == 1) {
      return true;
    }
    dest.resize(srclen / 2);
    const char *psrc = src.data();
    const char *pend = psrc + srclen;
    char *pdest = (char*)dest.data();
    int i=0;
    while (psrc < pend) {
      pdest[i++] = parseU8(psrc);
      psrc += 2;
    }
    return false;
  }

protected:
  static bool _initLut(uint8_t *lut) {
    for (int i=0; i < 256; i++) { lut[i] = (uint8_t)0; }
    for (auto i='0'; i <= '9'; i++) { lut[(int)i] = (uint8_t)(i - '0'); }
    for (auto i='A'; i <= 'F'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'A');}
    for (auto i='a'; i <= 'f'; i++) { lut[(int)i] = 10 + (uint8_t)(i - 'a');}
    return true;
  }
  static uint8_t* _lut() {
    static uint8_t lut[256];
    static bool isInitialized=_initLut(lut);
    return lut;
  }
  static inline uint8_t CVAL(const char c) {
    return _lut()[(uint8_t)c];
  }

};
