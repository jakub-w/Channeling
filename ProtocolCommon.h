// Copyright (C) 2020 by Jakub Wojciech

// This file is part of Channeling

// Lelo Remote Music Player is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.

// Lelo Remote Music Player is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Lelo Remote Music Player. If not, see
// <https://www.gnu.org/licenses/>.

#ifndef PROTOCOLCOMMON_H
#define PROTOCOLCOMMON_H

#include <array>
#include <iostream>

#include "msgpack.hpp"
#include "tl/expected.hpp"
#include "zmq.hpp"

using CryptoKey = std::array<unsigned char, 32>;
using EncKeys = msgpack::type::tuple<CryptoKey, CryptoKey>;
// using EncKeys = std::tuple<CryptoKey, CryptoKey>;
using PartialMessage = std::string;
using Bytes = std::vector<unsigned char>;

enum class MessageType : int {
  PROTOCOL_ERROR = -3,
  BAD_MESSAGE = -2,
  UNKNOWN = -1,
  ACK,
  ID,
  AUTH,
  DENY,
  AUTH_CONFIRM,
  AUTH_FINISHED,
  ENCRYPTED_DATA
};
MSGPACK_ADD_ENUM(MessageType);

enum class ClientMessageType {
  PROTOCOL_ERROR = -1,
  DATA = 0
};
MSGPACK_ADD_ENUM(ClientMessageType);


constexpr auto MessageTypeName(MessageType type) {
  switch (type) {
    case MessageType::PROTOCOL_ERROR:
      return "PROTOCOL_ERROR";
    case MessageType::BAD_MESSAGE:
      return "BAD_MESSAGE";
    case MessageType::UNKNOWN:
      return "UNKNOWN";
    case MessageType::ACK:
      return "ACK";
    case MessageType::ID:
      return "ID";
    case MessageType::AUTH:
      return "AUTH";
    case MessageType::DENY:
      return "DENY";
    case MessageType::AUTH_CONFIRM:
      return "AUTH_CONFIRM";
    case MessageType::AUTH_FINISHED:
      return "AUTH_FINISHED";
    case MessageType::ENCRYPTED_DATA:
      return "ENCRYPTED_DATA";
  }
  return "Unknown type";
}

template <typename T>
tl::expected<T, std::error_code>
Unpack(const char* data, std::size_t size, std::size_t& offset) {
  try {
    const auto handle = msgpack::unpack(data, size, offset);
    const auto object = handle.get();
    return object.as<T>();
  // } catch (const msgpack::unpack_error& e) {
  } catch (const std::exception& e) {
    std::cerr << "Unpacking error: " << e.what() << '\n';
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
  // } catch (const msgpack::unpack_error& e) {
  } catch (const std::exception& e) {
    std::cerr << "Unpacking error: " << e.what() << '\n';
    return tl::unexpected{std::make_error_code(
        std::errc::no_message_available)};
  }
}

inline std::string pack_message_type(MessageType type) {
  std::stringstream buffer;
  msgpack::pack(buffer, type);
  return buffer.str();
}

namespace{
template <typename Arg>
void make_msg_internal(std::stringstream& buffer, const Arg& arg) {
  msgpack::pack(buffer, arg);
}

template <typename Arg, typename... Args>
void make_msg_internal(std::stringstream& buffer,
                       const Arg& arg, const Args&... rest) {
  msgpack::pack(buffer, arg);
  make_msg_internal(buffer, rest...);
}
}

template <typename... Args>
zmq::message_t make_msg(const Args&... args) {
  std::stringstream buffer;
  make_msg_internal(buffer, args...);
  const auto buffer_str = buffer.str();

  return zmq::message_t{buffer_str.data(), buffer_str.size()};
}

#endif /* PROTOCOLCOMMON_H */
