#pragma once

#include <map>
#include <string>
#include <vector>
#include <unordered_map>

#include <type_traits>
#include <locale>

class ErrorBase {
public:
  virtual std::string getShortMessage() const = 0;
  virtual std::string getFullMessage() const = 0;
  virtual std::string getShortMessageRecursive() const = 0;
  virtual std::string getFullMessageRecursive() const = 0;
  virtual ~ErrorBase() = default;
  ErrorBase() = default;
  ErrorBase(const ErrorBase& other) = default;
};

template <typename ErrorCodeEnumType>
class Error final : public ErrorBase {
private:
  static std::string getErrorTypeName() {
    return "";//boost::core::demangle(typeid(ErrorCodeEnumType).name());
  }

public:
  using SelfType = Error<ErrorCodeEnumType>;

  explicit Error(ErrorCodeEnumType error_code,
                 std::string message,
                 std::unique_ptr<ErrorBase> underlying_error = nullptr)
  : errorCode_(error_code),
  message_(std::move(message)),
  underlyingError_(std::move(underlying_error)) {}

  virtual ~Error() = default;

  Error(Error&& other) = default;
  Error(const Error& other) = delete;

  Error& operator=(Error&& other) = default;
  Error& operator=(const Error& other) = delete;

  ErrorCodeEnumType getErrorCode() const {
    return errorCode_;
  }

  bool hasUnderlyingError() const {
    return underlyingError_ != nullptr;
  }

  const ErrorBase& getUnderlyingError() const {
    return *underlyingError_;
  }

  std::unique_ptr<ErrorBase> takeUnderlyingError() const {
    return std::move(underlyingError_);
  }

  std::string getShortMessage() const override {
    return getErrorTypeName() + " " +
    std::to_string(static_cast<int>(errorCode_));
  }

  std::string getFullMessage() const override {
    std::string full_message = getShortMessage();
    if (message_.size() > 0) {
      full_message += " (" + message_ + ")";
    }
    return full_message;
  }

  std::string getShortMessageRecursive() const override {
    std::string full_message = getShortMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getShortMessageRecursive();
    }
    return full_message;
  }

  std::string getFullMessageRecursive() const override {
    std::string full_message = getFullMessage();
    if (underlyingError_) {
      full_message += " <- " + underlyingError_->getFullMessageRecursive();
    }
    return full_message;
  }

  void appendToMessage(const std::string& text) {
    message_.append(text);
  }

private:
  ErrorCodeEnumType errorCode_;
  std::string message_;
  std::unique_ptr<ErrorBase> underlyingError_;
};

template <class T>
inline bool operator==(const Error<T>& lhs, const Error<T>& rhs) {
  return lhs.getErrorCode() == rhs.getErrorCode();
}

template <class T>
inline bool operator==(const Error<T>* lhs, const T rhs) {
  return lhs->getErrorCode() == rhs;
}

template <class T>
inline bool operator==(const Error<T>& lhs, const T rhs) {
  return lhs.getErrorCode() == rhs;
}

template <class T>
inline bool operator==(const ErrorBase& lhs, const T rhs) {
  try {
    const Error<T>& casted_lhs = dynamic_cast<const Error<T>&>(lhs);
    return casted_lhs == rhs;
  } catch (std::bad_cast _) {
    return false;
  }
}

template <class T>
inline bool operator==(const ErrorBase* lhs, const T rhs) {
  auto casted_lhs = dynamic_cast<const Error<T>*>(lhs);
  return casted_lhs != nullptr && casted_lhs == rhs;
}

inline std::ostream& operator<<(std::ostream& out, const ErrorBase& error) {
  out << error.getFullMessageRecursive();
  return out;
}

template <typename ErrorCodeEnumType>
Error<ErrorCodeEnumType> createError(
                                     ErrorCodeEnumType error_code,
                                     std::string message,
                                     std::unique_ptr<ErrorBase> underlying_error = nullptr) {
  return Error<ErrorCodeEnumType>(
                                  error_code, std::move(message), std::move(underlying_error));
}

template <typename ErrorCodeEnumType, typename OtherErrorCodeEnumType>
Error<ErrorCodeEnumType> createError(
                                     ErrorCodeEnumType error_code,
                                     std::string message,
                                     Error<OtherErrorCodeEnumType> underlying_error) {
  return Error<ErrorCodeEnumType>(
                                  error_code,
                                  std::move(message),
                                  std::make_shared<Error<OtherErrorCodeEnumType>>(
                                                                                  std::move(underlying_error)));
}

template <typename ErrorType,
typename ValueType,
typename = typename std::enable_if<
std::is_base_of<ErrorBase, ErrorType>::value>::type>
inline ErrorType operator<<(ErrorType&& error, const ValueType& value) {
  std::ostringstream ostr{};
  ostr << value;
  error.appendToMessage(ostr.str());
  return std::forward<ErrorType>(error);
}


template <typename ValueType_, typename ErrorCodeEnumType>
class Expected final {
 public:
  using ValueType = ValueType_;
  using ErrorType = Error<ErrorCodeEnumType>;
  using SelfType = Expected<ValueType, ErrorCodeEnumType>;

  static_assert(
      !std::is_pointer<ValueType>::value,
      "Please do not use raw pointers as expected value, "
      "use smart pointers instead. See CppCoreGuidelines for explanation. "
      "https://github.com/isocpp/CppCoreGuidelines/blob/master/"
      "CppCoreGuidelines.md#Rf-unique_ptr");
  static_assert(!std::is_reference<ValueType>::value,
                "Expected does not support reference as a value type");
  static_assert(std::is_enum<ErrorCodeEnumType>::value,
                "ErrorCodeEnumType template parameter must be enum");

 public:
  Expected(ValueType value) : object_((void*)value) {
    //fprintf(stderr, "new value");
  }

  Expected(ErrorType error) : object_((void*)&error) {
    fprintf(stderr, "new errtype");
  }

  explicit Expected(ErrorCodeEnumType code, std::string message)
      : object_{ErrorType(code, message)} {}

  Expected() = delete;
  Expected(ErrorBase* error) = delete;

  Expected(Expected&& other)
      : object_(std::move(other.object_)), errorChecked_(other.errorChecked_) {
    other.errorChecked_ = true;
  }

  Expected& operator=(Expected&& other) {
    if (this != &other) {
      //errorChecked_.verify("Expected was not checked before assigning");

      object_ = std::move(other.object_);
      errorChecked_ = other.errorChecked_;
      other.errorChecked_.set(true);
    }
    return *this;
  }

  Expected(const Expected&) = delete;
  Expected& operator=(const Expected& other) = delete;

  ~Expected() {
    //errorChecked_.verify("Expected was not checked before destruction");
  }

  static SelfType success(ValueType value) {
    return SelfType{std::move(value)};
  }

  static SelfType failure(std::string message) {
    auto defaultCode = ErrorCodeEnumType{};
    return SelfType(defaultCode, std::move(message));
  }

  static SelfType failure(ErrorCodeEnumType code, std::string message) {
    return SelfType(code, std::move(message));
  }

  ErrorType takeError() && = delete;
  ErrorType takeError() & {
    verifyIsError();
    return std::move((ErrorType)object_);//boost::get<ErrorType>(object_));
  }

  const ErrorType& getError() const&& = delete;
  const ErrorType& getError() const& {
    verifyIsError();
    return (ErrorType)object_;//boost::get<ErrorType>(object_);
  }

  ErrorCodeEnumType getErrorCode() const&& = delete;
  ErrorCodeEnumType getErrorCode() const& {
    return getError().getErrorCode();
  }

  bool isError() const noexcept {
    //errorChecked_ = true;
    return false;//object_.which() == kErrorType_;
  }

  bool isValue() const noexcept {
    return !isError();
  }

  explicit operator bool() const noexcept {
    return isValue();
  }

  ValueType& get() && = delete;
  ValueType& get() & {
    verifyIsValue();
    return *(ValueType*)object_;//boost::get<ValueType>(object_);
  }

  const ValueType& get() const&& = delete;
  const ValueType& get() const& {
    verifyIsValue();
    return (ValueType)object_;//boost::get<ValueType>(object_);
  }

  ValueType take() && = delete;
  ValueType take() & {
    return std::move(get());
  }

  template <typename ValueTypeUniversal = ValueType>
  typename std::enable_if<
      std::is_same<typename std::decay<ValueTypeUniversal>::type,
                   ValueType>::value,
      ValueType>::type
  takeOr(ValueTypeUniversal&& defaultValue) {
    if (isError()) {
      return std::forward<ValueTypeUniversal>(defaultValue);
    }
    return (ValueType)object_;// get();//std::move(get());
  }

  ValueType* operator->() && = delete;
  ValueType* operator->() & {
    return &get();
  }

  const ValueType* operator->() const&& = delete;
  const ValueType* operator->() const& {
    return &get();
  }

  ValueType& operator*() && = delete;
  ValueType& operator*() & {
    return get();
  }

  const ValueType& operator*() const&& = delete;
  const ValueType& operator*() const& {
    return get();
  }

 private:
  inline void verifyIsError() const {
//    debug_only::verify([this]() { return object_.which() == kErrorType_; },
//                       "Do not try to get error from Expected with value");
  }

  inline void verifyIsValue() const {
 //   debug_only::verify([this]() { return object_.which() == kValueType_; },
   //                    "Do not try to get value from Expected with error");
  }

 private:
  void * object_;//boost::variant<ValueType, ErrorType> object_;
  enum ETypeId {
    kValueType_ = 0,
    kErrorType_ = 1,
  };
  bool errorChecked_ = false;
};

enum class ConversionError {
  InvalidArgument,
  OutOfRange,
  Unknown,
};

template <typename ToType, typename FromType>
inline typename std::enable_if<
    std::is_same<ToType,
                 typename std::remove_cv<typename std::remove_reference<
                     FromType>::type>::type>::value,
    Expected<ToType, ConversionError>>::type
tryTo(FromType&& from) {
  return std::forward<FromType>(from);
}

namespace impl {

template <typename Type>
struct IsStlString {
  static constexpr bool value = std::is_same<Type, std::string>::value ||
                                std::is_same<Type, std::wstring>::value;
};

template <typename Type>
struct IsInteger {
  static constexpr bool value =
      std::is_integral<Type>::value && !std::is_same<Type, bool>::value;
};

template <typename FromType,
          typename ToType,
          typename IntType,
          typename =
              typename std::enable_if<std::is_same<ToType, IntType>::value &&
                                          IsStlString<FromType>::value,
                                      IntType>::type>
struct IsConversionFromStringToIntEnabledFor {
  using type = IntType;
};

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType, ToType, int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoi(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stol(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoll(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType,
                                                   ToType,
                                                   unsigned long long int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoull(from, &pos, base);
}


Expected<bool, ConversionError> stringToBool(std::string from) {
  static const auto table = std::unordered_map<std::string, bool>{
      {"1", true},
      {"0", false},
      {"y", true},
      {"yes", true},
      {"n", false},
      {"no", false},
      {"t", true},
      {"true", true},
      {"f", false},
      {"false", false},
      {"ok", true},
      {"disable", false},
      {"enable", true},
  };
  using CharType = std::string::value_type;
  // Classic locale could be used here because all available string
  // representations of boolean have ascii encoding. It must be a bit faster.
  static const auto& ctype =
      std::use_facet<std::ctype<CharType>>(std::locale::classic());
  for (auto& ch : from) {
    ch = ctype.tolower(ch);
  }
  const auto it = table.find(from);
  if (it == table.end()) {
    return createError(ConversionError::InvalidArgument,
                       "Wrong string representation of boolean ");//           << boost::io::quoted(from);
  }
  return it->second;
}

} // namespace impl

  /**
   * Template tryTo for [w]string to integer conversion
   */
  template <typename ToType, typename FromType>
inline typename std::enable_if<impl::IsInteger<ToType>::value &&
  impl::IsStlString<FromType>::value,
  Expected<ToType, ConversionError>>::type
  tryTo(const FromType& from, const int base = 10) noexcept {
    try {
      return impl::throwingStringToInt<ToType>(from, base);
    } catch (const std::invalid_argument& ia) {
      return createError(ConversionError::InvalidArgument,
                         "If no conversion could be performed. ")
      << ia.what();
    } catch (const std::out_of_range& oor) {
      return createError(ConversionError::OutOfRange,
                         "Value read is out of the range of representable values "
                         "by an int. ")
      << oor.what();
    } catch (...) {
      return createError(ConversionError::Unknown,
                         "Unknown error during conversion ")
      << (typeid(FromType).name()) << " to "
      << (typeid(ToType).name()) << " base " << base;
    }
  }


/**
 * Parsing general representation of boolean value in string.
 *     "1" : true
 *     "0" : false
 *     "y" : true
 *   "yes" : true
 *     "n" : false
 *    "no" : false
 *   ... and so on
 *   For the full list of possible valid values @see stringToBool definition
 */
template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, bool>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(std::string from) {
  return impl::stringToBool(std::move(from));
}







struct OldAuditParser {
  static std::string INTEGER(long val) {
    return std::to_string(val);
//    char tmp[32];
//    snprintf(tmp,sizeof(tmp), "%lu",(unsigned long)val);
  }

  static std::string ip4FromSaddr(const std::string& saddr, unsigned short offset) {
    long const result = tryTo<long>(saddr.substr(offset, 8), 16).takeOr(0l);
    return std::to_string((result & 0xff000000) >> 24) + '.' +
    std::to_string((result & 0x00ff0000) >> 16) + '.' +
    std::to_string((result & 0x0000ff00) >> 8) + '.' +
    std::to_string((result & 0x000000ff));
  }

  static bool parseSockAddr(const std::string saddr, std::map<std::string,std::string> &row) {

    std::string address_column;
    std::string port_column;
    if (row["action"] == "bind") {
      address_column = "local_address";
      port_column = "local_port";

      row["remote_address"] = "0";
      row["remote_port"] = "0";
    } else {
      address_column = "remote_address";
      port_column = "remote_port";

      row["local_address"] = "0";
      row["local_port"] = "0";
    }

    // The protocol is not included in the audit message.
    if (saddr[0] == '0' && saddr[1] == '2') {
      // IPv4
      row["family"] = "2";
      long const result = tryTo<long>(saddr.substr(4, 4), 16).takeOr(0l);
      row[port_column] = INTEGER(result);
      row[address_column] = ip4FromSaddr(saddr, 8);
    } else if (saddr[0] == '0' && saddr[1] == 'A') {
      // IPv6
      row["family"] = "10";
      long const result = tryTo<long>(saddr.substr(4, 4), 16).takeOr(0l);
      row[port_column] = INTEGER(result);
      std::string address;
      for (size_t i = 0; i < 8; ++i) {
        address += saddr.substr(16 + (i * 4), 4);
        if (i == 0 || i % 7 != 0) {
          address += ':';
        }
      }
      //boost::algorithm::to_lower(address);

      char *mess = (char *)address.data();
      for (auto i = 0; i < address.size(); i++) {
        mess[i] = tolower(mess[i]);
      }


      row[address_column] = std::move(address);

    } else if (saddr[0] == '0' && saddr[1] == '1' && saddr.size() > 6) {

      row["family"] = '1';
      off_t begin = (saddr[4] == '0' && saddr[5] == '0') ? 6 : 4;
      auto end = saddr.substr(begin).find("00");
      end = (end == std::string::npos) ? saddr.size() : end + 4;
      //try {
        row["socket"] = /*boost::algorithm::unhex*/(saddr.substr(begin, end - begin));
      //} catch (const boost::algorithm::hex_decode_error& e) {
        //row["socket"] = "unknown";
      //}

    } else {

      return false;
    }

  return true;
  }
};
