#ifndef PROTOCOLCOMMON_H
#define PROTOCOLCOMMON_H

#include <array>

#include "msgpack.hpp"
#include "tl/expected.hpp"

using CryptoKey = std::array<unsigned char, 32>;

enum class MessageType : int {
  BAD_MESSAGE = -2,
  UNKNOWN = -1,
  AUTH,
  DENY,
  AUTH_CONFIRM,
};
MSGPACK_ADD_ENUM(MessageType);

constexpr auto MessageTypeName(MessageType type) {
  switch (type) {
    case MessageType::BAD_MESSAGE:
      return "BAD_MESSAGE";
      break;
    case MessageType::UNKNOWN:
      return "UNKNOWN";
      break;
    case MessageType::AUTH:
      return "AUTH";
      break;
    case MessageType::DENY:
      return "DENY";
      break;
    case MessageType::AUTH_CONFIRM:
      return "AUTH_CONFIRM";
      break;
  }
}

template <typename T>
tl::expected<T, std::error_code>
Unpack(const char* data, std::size_t size, std::size_t& offset) {
  try {
    const auto handle = msgpack::unpack(data, size, offset);
    const auto object = handle.get();
    return object.as<T>();
  } catch (const msgpack::unpack_error& e) {
    return tl::unexpected{std::make_error_code(
        std::errc::no_message_available)};
  }
}

template <typename T>
tl::expected<T, std::error_code>
Unpack(const char* data, std::size_t size) {
  try {
    const auto handle = msgpack::unpack(data, size);
    const auto object = handle.get();
    return object.as<T>();
  } catch (const msgpack::unpack_error& e) {
    return tl::unexpected{std::make_error_code(
        std::errc::no_message_available)};
  }
}

#endif /* PROTOCOLCOMMON_H */
