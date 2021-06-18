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

#ifndef CHANNELING_PROTOCOLCOMMON_H
#define CHANNELING_PROTOCOLCOMMON_H

#include <array>

#include <msgpack.hpp>
#include <tl/expected.hpp>
#include <zmq.hpp>
#include <zmq_addon.hpp>

#include "Logging.h"

namespace Channeling {
using CryptoKey = std::array<unsigned char, 32>;
using EncKeys = msgpack::type::tuple<CryptoKey, CryptoKey>;
// using EncKeys = std::tuple<CryptoKey, CryptoKey>;
using PartialMessage = std::string;
using Bytes = std::vector<unsigned char>;
using req_id_t = std::uint32_t;

enum class MessageType : int {
  PROTOCOL_ERROR = -3,
  BAD_MESSAGE = -2,
  UNKNOWN = -1,
  ACK,
  ID,
  AUTH_REQUEST,
  AUTH,
  DENY,
  AUTH_CONFIRM,
  AUTH_FINISHED,
  ENCRYPTED_DATA
};

enum class ClientMessageType {
  PROTOCOL_ERROR = -1,
  DATA = 0
};

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
    case MessageType::AUTH_REQUEST:
      return "AUTH_REQUEST";
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
  } catch (const std::exception& e) {
    LOG_ERROR("Unpacking error: {}", e.what());
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
  } catch (const std::exception& e) {
    LOG_ERROR("Unpacking error: {}", e.what());
    return tl::unexpected{std::make_error_code(
        std::errc::no_message_available)};
  }
}

inline std::string pack_message_type(MessageType type) {
  std::stringstream buffer;
  msgpack::pack(buffer, type);
  return buffer.str();
}

template <typename... Args>
zmq::message_t make_msg(const Args&... args) {
  std::stringstream buffer;
  (msgpack::pack(buffer, args), ...);
  const auto buffer_str = buffer.str();

  return zmq::message_t(buffer_str.data(), buffer_str.size());
}

inline auto make_unexpected(std::errc errc) {
  return tl::unexpected{std::make_error_code(errc)};
}

inline std::error_code recv_from_dealer(
      zmq::socket_ref socket, zmq::message_t& message,
      zmq::recv_flags flags = zmq::recv_flags::none) {
  std::vector<zmq::message_t> msgs;
  while (not zmq::recv_multipart(socket, std::back_inserter(msgs), flags));
  if (2 != msgs.size()) {
    return std::make_error_code(std::errc::bad_message);
  }
  message = std::move(msgs[1]);
  return {};
}

inline std::shared_ptr<zmq::context_t> get_context() {
  static std::weak_ptr<zmq::context_t> ctx_;
  static std::mutex mtx_;

  std::lock_guard lock{mtx_};

  if (ctx_.expired()) {
    auto ctx = std::make_shared<zmq::context_t>();
    ctx_ = ctx;
    return ctx;
  }

  return ctx_.lock();
}
}

MSGPACK_ADD_ENUM(Channeling::MessageType);
MSGPACK_ADD_ENUM(Channeling::ClientMessageType);

#endif /* CHANNELING_PROTOCOLCOMMON_H */
